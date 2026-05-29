from collections.abc import AsyncGenerator, AsyncIterator, Callable, Coroutine, Generator
from typing import (
    TypeVar,
)

RETURN_TYPE = TypeVar("RETURN_TYPE")

DependencyCallable = Callable[
    ...,
    RETURN_TYPE
    | Coroutine[None, None, RETURN_TYPE]
    | AsyncGenerator[RETURN_TYPE]
    | Generator[RETURN_TYPE]
    | AsyncIterator[RETURN_TYPE],
]
