---
title: Home
description: An asynchronous Python SDK for Frank Energie electricity, gas, and smart-energy data.
hide:
  - toc
---

<div class="fe-hero">
  <div class="fe-hero__eyebrow">OPEN-SOURCE · ASYNCIO · PYTHON 3.12+</div>
  <h1>Frank Energie data,<span> ready for Python.</span></h1>
  <p class="fe-hero__lead">An asynchronous client for dynamic electricity and gas prices, account data, and supported smart-energy features. Built with typed models, explicit error handling, and Home Assistant integrations in mind.</p>
  <div class="fe-hero__actions">
    <a class="fe-button fe-button--primary" href="getting-started/">Get started <span aria-hidden="true">→</span></a>
    <a class="fe-button fe-button--secondary" href="https://github.com/HiDiHo01/python-frank-energie">Explore GitHub</a>
  </div>
  <div class="fe-hero__meta"><span>Async by design</span><span>Python 3.12+</span><span>Community maintained</span></div>
</div>

## Everything in one client

<div class="fe-feature-grid">
  <a class="fe-feature" href="authentication/"><span class="fe-feature__kicker">01 / Access</span><strong>Authentication</strong><span>JWT credentials, token renewal, and clear lifecycle boundaries.</span><span class="fe-feature__arrow" aria-hidden="true">↗</span></a>
  <a class="fe-feature" href="weighted-average-prices/"><span class="fe-feature__kicker">02 / Markets</span><strong>Price data</strong><span>Electricity, gas, weighted average prices, and nullable results.</span><span class="fe-feature__arrow" aria-hidden="true">↗</span></a>
  <a class="fe-feature" href="smart-hvac/"><span class="fe-feature__kicker">03 / Devices</span><strong>Smart HVAC</strong><span>Site feature status, device inventory, and connected controls.</span><span class="fe-feature__arrow" aria-hidden="true">↗</span></a>
  <a class="fe-feature" href="smart-pv/"><span class="fe-feature__kicker">04 / Solar</span><strong>Smart PV</strong><span>PV inventory, system summaries, and provider-aware models.</span><span class="fe-feature__arrow" aria-hidden="true">↗</span></a>
</div>

## Install in one command

```bash
python -m pip install python-frank-energie
```

Start with the [installation and first request guide](getting-started.md), or browse the [architecture reference](ARCHITECTURE.md) to understand the client, models, and error contracts.

!!! note "Independent project"
    This library is community maintained. It is **not developed, affiliated with, or supported by Frank Energie**. Some APIs require an eligible account, connected device, or activated service.

## Built for automation

Use native **async/await** patterns and structured models rather than parsing raw responses in consuming applications. Home Assistant owns its polling, caching, credentials, and coordinator lifecycle; the SDK provides the underlying API client.

- [Explore API architecture](ARCHITECTURE.md) — responsibilities and compatibility guarantees
- [Learn about rate limiting](rate-limits.md) — network errors and retry semantics
- [Read the privacy policy](privacy-policy/index.md) — handling sensitive data

Looking for the Home Assistant integration? Visit [home-assistant-frank_energie](https://github.com/HiDiHo01/home-assistant-frank_energie).
