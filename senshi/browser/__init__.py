"""
Senshi browser engine -- Playwright-based browser automation.

Phase 1 (v1.0):
  runtime.py      - BrowserRuntime (lifecycle, stealth, SPA-aware nav)
  interceptor.py  - TrafficInterceptor (capture all XHR/fetch/WS)
  interactor.py   - AppInteractor (click-based SPA crawling)
  analyzer.py     - EndpointAnalyzer (traffic -> AttackSurface)
"""
