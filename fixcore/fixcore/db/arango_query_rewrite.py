from typing import List, cast

from attr import evolve

from fixcore.db.model import QueryModel
from fixcore.model.model import predefined_kinds_by_name
from fixcore.query.model import (
    Query,
    Predicate,
    FulltextTerm,
    Term,
    ContextTerm,
    MergeTerm,
    CombinedTerm,
    IsTerm,
    NotTerm,
)


def add_is_term(query_model: QueryModel) -> Query:
    model = query_model.model

    def and_combined(term: Term) -> bool:
        if isinstance(term, NotTerm):
            return True
        return isinstance(term, CombinedTerm) and term.op == "and"

    def no_context(term: Term) -> bool:
        return not isinstance(term, (MergeTerm, ContextTerm))

    def combine_term_if_possible(term: Term, predicates: List[Predicate]) -> Term:
        kinds = set()
        for pred in predicates:
            for res in query_model.owners(pred.name):
                if res.fqn not in predefined_kinds_by_name:
                    kinds.add(res.fqn)
        kinds.discard("resource")  # all resources have this base kind - ignore it
        return IsTerm(kinds=sorted(kinds)).and_term(term) if kinds else term

    def change_term(term: Term) -> Term:
        if isinstance(term, CombinedTerm) and term.op == "or":
            left = change_term(term.left)
            right = change_term(term.right)
            return evolve(term, left=left, right=right)
        elif isinstance(term, CombinedTerm) and term.op == "and":
            li = term.left.find_term(lambda t: isinstance(t, IsTerm), and_combined)
            ri = term.right.find_term(lambda t: isinstance(t, IsTerm), and_combined)
            if li is None and ri is None:
                predicates = cast(List[Predicate], term.find_terms(lambda t: isinstance(t, Predicate), no_context))
                contexts = cast(List[ContextTerm], term.find_terms(lambda t: isinstance(t, ContextTerm), no_context))
                all_preds = predicates + [pred for ctx in contexts for pred in ctx.visible_predicates()]
                return combine_term_if_possible(term, all_preds)
        elif isinstance(term, NotTerm):
            return NotTerm(change_term(term.term))
        elif isinstance(term, Predicate):
            return combine_term_if_possible(term, [term])
        elif isinstance(term, ContextTerm):
            return combine_term_if_possible(term, term.visible_predicates())
        elif isinstance(term, MergeTerm):
            pre = change_term(term.pre_filter)
            post = change_term(term.post_filter) if term.post_filter else None
            queries = [evolve(mq, query=add_is_term(QueryModel(mq.query, model))) for mq in term.merge]
            return MergeTerm(pre_filter=pre, post_filter=post, merge=queries)
        return term

    part = query_model.query.first_part
    part = evolve(part, term=change_term(part.term))
    return evolve(query_model.query, parts=query_model.query.parts[:-1] + [part])


def rewrite_query(
    query_model: QueryModel,
) -> Query:
    q = query_model.query
    p = q.first_part

    #  check for single tags predicate. use fulltext index: tags.foo==bar --> "bar" and tags.foo==bar
    if isinstance(p.term, Predicate) and p.term.name.startswith("reported.tags.") and p.term.op in ("==", "in"):
        value = " ".join(p.term.value) if isinstance(p.term.value, list) else str(p.term.value)
        part = evolve(p, term=FulltextTerm(value).and_term(p.term))
        return evolve(q, parts=q.parts[:-1] + [part])

    # try to add an IsTerm if not already provided
    q = add_is_term(query_model)

    return q
