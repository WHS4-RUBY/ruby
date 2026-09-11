# Benchmark Manager Design Contract

## Product and audience

This is a local operations console for the person running controlled web-defense experiments. The primary tasks are selecting a registered vulnerability, confirming the active stack state, composing a bounded campaign, and reading results without opening raw JSON first.

## Visual direction

- Dense operations console, quiet and technical
- Dark graphite surfaces with strong text contrast
- Cyan for interaction, green for safe or complete, amber for running or caution, red for vulnerable or failed
- Typography uses the system UI stack for labels and a monospace stack for identifiers, paths, numbers, and logs
- Borders and spacing establish hierarchy. Shadows, gradients, oversized marketing headings, decorative cards, and animation are excluded

## Layout and density

- A compact persistent header answers what is running and provides the two global actions
- The first viewport shows system state and the target selection workspace
- Target selection uses a searchable list and a separate detail pane
- Experiment settings expose common choices first and bounded numeric controls in an advanced section
- Results use a master-detail layout with summary metrics before raw evidence
- Desktop content width is 1480px. Below 980px, split panes become a single column without hiding actions

## Component semantics

- Status badges describe real state only
- Red is reserved for active vulnerability, failures, and destructive or costly confirmation
- Safe mode is always a first-class action
- Campaign start and stack switching require confirmation
- Empty, loading, error, disabled, selected, focus and running states are visible
- Raw JSON and logs remain available but do not lead the result view

## Known gaps

- The backend does not expose per-trial live progress, so running progress shows completed trials only when a summary exists
- Results are local files and are not shared or synchronized by this UI
