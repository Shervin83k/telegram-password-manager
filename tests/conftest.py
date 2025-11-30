import pytest
import asyncio
from aiogram import Bot, Dispatcher
from aiogram.fsm.storage.memory import MemoryStorage


@pytest.fixture
def storage():
    """Provide in-memory storage for tests."""
    return MemoryStorage()


@pytest.fixture
def bot():
    """Provide Bot instance with test token."""
    return Bot(token="test")


@pytest.fixture
def dp(storage):
    """Provide Dispatcher instance with memory storage."""
    return Dispatcher(storage=storage)


@pytest.fixture(scope="session")
def event_loop():
    """Provide event loop for async tests."""
    loop = asyncio.get_event_loop()
    yield loop
    loop.close()