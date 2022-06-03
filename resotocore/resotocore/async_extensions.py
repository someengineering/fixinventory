import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Any, Callable, Optional, cast

# Global bounded thread pool to bridge sync io with asyncio.
GlobalAsyncPool: Optional[ThreadPoolExecutor] = None


async def run_async(sync_func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    global GlobalAsyncPool  # pylint: disable=global-statement
    if GlobalAsyncPool is None:
        # The maximum number of threads is defined explicitly here, since the default is very limited.
        GlobalAsyncPool = ThreadPoolExecutor(1024, "async")  # pylint: disable=consider-using-with
    # run in executor does not allow passing kwargs. apply them partially here if defined
    fn_with_args = cast(Callable[..., Any], sync_func if not kwargs else partial(sync_func, **kwargs))
    return await asyncio.get_event_loop().run_in_executor(GlobalAsyncPool, fn_with_args, *args)
