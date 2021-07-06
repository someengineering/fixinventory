import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import partial

# global unbounded thread pool to bridge sync io with asyncio
from typing import Any

GlobalAsyncPool = ThreadPoolExecutor(None, "global_async")  # pylint: disable=consider-using-with


async def run_async(sync_func, *args: Any, **kwargs: Any) -> Any:  # type: ignore
    # run in executor does not allow passing kwargs. apply them partially here if defined
    fn_with_args = sync_func if not kwargs else partial(sync_func, **kwargs)
    return await asyncio.get_event_loop().run_in_executor(GlobalAsyncPool, fn_with_args, *args)
