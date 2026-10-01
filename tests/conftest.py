from datetime import datetime, timedelta, timezone

import pytest

from intellidetect.models import Event
from intellidetect.pipeline import run_pipeline
from intellidetect.simulator import Simulator

T0 = datetime(2026, 3, 10, 8, 0, 0, tzinfo=timezone.utc)


def make_event(offset=0, kind="auth_failure", source="auth", **kw):
    """Build an Event ``offset`` seconds after T0."""
    return Event(ts=T0 + timedelta(seconds=offset), source=source, kind=kind, **kw)


@pytest.fixture(scope="session")
def sim_dir(tmp_path_factory):
    out = tmp_path_factory.mktemp("logs")
    Simulator(seed=1337, start=T0).generate().write(out)
    return out


@pytest.fixture(scope="session")
def result(sim_dir):
    return run_pipeline(sim_dir)
