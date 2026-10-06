# Detection workspace design

## 1. Direction
Keep the existing Primer-inspired monitoring UI. The primary task is to choose
a client flow, scan its requests, and open one request for evidence. Technical
aggregation views and filters remain available through progressive disclosure.
Do not change detection scores, policies, identity semantics, or API contracts.

References:
- https://docs.mitmproxy.org/stable/ - flow list and selected request inspection.
- https://www.zaproxy.org/docs/desktop/ui/ - separate primary work and supporting detail.
- https://github.com/arkime/arkime - searchable session investigation.
- https://github.com/changeroa/StyleGallery/blob/main/patterns/split-sidebar/list-detail.md
  - list/detail spatial relationship, adapted to the existing scroll containers.

## 2. Color
Use the existing CSS variables in public/dashboard.html. Light/dark pairs:
background --bg (#f6f8fa/#010409), surface --surface (#ffffff/#0d1117),
muted surface --surface-muted (#f6f8fa/#151b23),
border --border (#d1d9e0/#30363d), text --text (#1f2328/#e6edf3),
secondary --text-2 (#3d444d/#c9d1d9), muted --muted (#59636e/#9198a1),
link/focus --blue (#0969da/#58a6ff), attack --red (#d1242f/#f85149),
warning --amber (#9a6700/#d29922), success --green (#1a7f37/#3fb950).
Selection uses --select-bg with a neutral border, not an accent edge.
Retain the existing semantic tag, badge, method, and JSON palettes.

## 3. Typography
Keep --font (Korean system/Pretendard stack) and --mono (system monospace).
Both dashboards load the official Pretendard Variable v1.3.9 stylesheet from
https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/variable/pretendardvariable.css.
It declares weights 45-920 and font-display: swap. Titles, prose and controls
use --font; URLs, identifiers, request fields and JSON retain --mono. The
existing system-font fallback applies when the external CDN is unavailable.
Body 14px, primary headings 16-20px, supporting labels 12-13px,
summary values 26px. On narrow screens inputs and primary content use 16px.
Technical paths truncate in rows and wrap in expanded detail.

## 4. Layout and spacing
Use the existing 4px spacing rhythm: 4, 8, 12, 16, 20, 24, 32, 48px.
Summary is a compact strip, not four competing feature cards.
List/detail is a 320px list and flexible request pane on desktop, stacked
below 1100px. List owns its bounded scroll; request log owns its bounded scroll.
The document scrolls for expanded supporting material. Use dynamic viewport
units. Expanded technical tables own horizontal scroll; primary content must
not overflow at 390px.

## 5. Components and states
- Navigation: primary investigation tab and disclosure for technical views.
  Retain selected tab semantics, counts, and keyboard-accessible native controls.
- Flow card: distinguish by observed IP and short ID; identity badge and attack
  labels retain their meaning. Scores and evidence stay visible without
  claiming a confirmed person or a probability.
- Disclosure: native details/summary for settings, help, connection evidence,
  and advanced log filters. Persist dynamic disclosure state across refresh.
  Active advanced filters are counted on the summary even while closed.
- Request row: newest first; button expands field table and optional raw JSON.
  Preserve focus, expanded rows, search caret and scroll anchor on refresh.
- Empty/error/loading: explain the missing records and the next action.
- Buttons: default, hover, selected tonal wash, visible keyboard focus, disabled.
- Full detail modal: a fixed header with close action, one scrolling content
  region, compact observation summary, then request rows. Keep score
  calculation, cumulative history, connection evidence, and raw feature
  metrics in four closed native disclosures. IP observations never show
  detection scores. Distinguish current attack score from historical maximum;
  a below-threshold score is not a declaration of safety. Raw JSON stays
  available in the analysis disclosure. Escape all observed values.
  Use 16px content padding on narrow screens, 20px on wide screens, existing
  12/14/16px type, and four summary cells reflowing to two. Focus close on
  opening, contain keyboard focus, and return focus to the opener on close.

## 6. Interaction
No decorative animation. Keep immediate native disclosure and existing
120-150ms feedback; reduced motion removes optional transitions.
Search and filtering never require a reload. Refresh every two seconds must
not close disclosures or remove the current input focus.

## 7. Accessibility
Visible search labels; native keyboard-operable summaries; mobile targets
at least 44px; statuses have text in addition to color. Retain escaped request
content, authentication, copy/export, and cross-dashboard request links.

## 8. Boundaries and validation
Scope is the detection dashboard only. Preserve existing uncommitted changes
in detection and defense. No extra dependencies and no commits.
Verify both themes at desktop/mobile, empty/populated states, selection,
search, advanced filters, details, full-screen logs and refresh persistence.
Browser QA fixtures are synthetic; they do not validate a deployed proxy.
