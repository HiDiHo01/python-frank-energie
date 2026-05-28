"""Tests for Frank Energie Smart PV implementation."""

import aiohttp
import pytest
from syrupy.assertion import SnapshotAssertion

from python_frank_energie import FrankEnergie

from . import load_fixtures

SIMPLE_DATA_URL = "frank-graphql-prod.graphcdn.app"


@pytest.mark.asyncio
@pytest.mark.allow_socket
async def test_smart_pv_systems(aresponses, snapshot: SnapshotAssertion):
    """Test smart_pv_systems query."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=load_fixtures("smart_pv_systems.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")
        pv_systems = await api.smart_pv_systems()
        await api.close()

    assert pv_systems is not None
    assert pv_systems == snapshot


@pytest.mark.asyncio
@pytest.mark.allow_socket
async def test_smart_pv_system_summary(aresponses, snapshot: SnapshotAssertion):
    """Test smart_pv_system_summary query."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=load_fixtures("smart_pv_system_summary.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")
        summary = await api.smart_pv_system_summary("pv-123")
        await api.close()

    assert summary is not None
    assert summary == snapshot


@pytest.mark.asyncio
@pytest.mark.allow_socket
async def test_user_smart_feed_in(aresponses, snapshot: SnapshotAssertion):
    """Test user_smart_feed_in query."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=load_fixtures("user_smart_feed_in.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")
        feed_in = await api.user_smart_feed_in()
        await api.close()

    assert feed_in is not None
    assert feed_in == snapshot


@pytest.mark.asyncio
@pytest.mark.allow_socket
async def test_enode_vehicles_parsing(aresponses, snapshot: SnapshotAssertion):
    """Test enode_vehicles parsing method."""
    aresponses.add(
        SIMPLE_DATA_URL,
        "/",
        "POST",
        aresponses.Response(
            text=load_fixtures("enode_vehicles.json"),
            status=200,
            headers={"Content-Type": "application/json"},
        ),
    )

    async with aiohttp.ClientSession() as session:
        api = FrankEnergie(session, auth_token="a", refresh_token="b")
        vehicles = await api.enode_vehicles()
        await api.close()

    assert vehicles is not None
    assert vehicles == snapshot
