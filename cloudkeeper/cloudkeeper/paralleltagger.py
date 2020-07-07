import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from typing import List
from cloudkeeper.baseresources import BaseResource


log = logging.getLogger(__name__)


class ParallelTagger:
    def __init__(self, max_workers: int = 50) -> None:
        self.max_workers = max_workers
        self._tag_lists = defaultdict(list)

    def add(self, resource: BaseResource, key, value, pt_key=None) -> None:
        if not isinstance(resource, BaseResource):
            raise ValueError(f"Resource {resource} is not a valid Cloudkeeper BaseResource")

        if pt_key is None:
            pt_key = uuid.uuid4().hex

        log.debug(f"Queuing parallel tag update of {key}: {value} for {resource.dname} with pt_key {pt_key}")
        self._tag_lists[pt_key].append({"resource": resource, "key": key, "value": value})

    def run(self):
        with ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="parallel_tagger") as executor:
            for tag_list in self._tag_lists.values():
                executor.submit(self.tag, tag_list)

    def tag(self, tag_list: List):
        for tag_info in tag_list:
            log.debug(f"Setting {tag_info['key']}: {tag_info['value']} for {tag_info['resource']}")
            tag_info["resource"].tags[tag_info["key"]] = tag_info["value"]
