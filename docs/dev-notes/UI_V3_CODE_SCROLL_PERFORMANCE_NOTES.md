# CyberVaultX UI V3 Code Fixes

This update is code-only. It focuses on the real Tkinter interface, not generated images.

## Fixed
- Mouse wheel scrolling now routes from child widgets to the active page canvas.
- Treeview/Text widgets scroll first; when they reach the edge, the page scroll remains responsive.
- Page scrollbars use a dark ttk style and auto-hide when content fits.
- Removed bright/native-looking scrollbar behavior from long tables.
- Reduced hard neon borders by replacing glow-card top stripes with subtle accent rails.
- Compacted the global topbar and metric cards to reduce wasted vertical space.
- Softened palette, borders, and card hierarchy so pages look cleaner and less heavy.
- Refresh pipeline no longer rebuilds every hidden heavy page on every small UI update.

## Why this matters
The previous V2 interface was visually stronger than the original, but it still felt heavy: many hard borders, bright scrollbars, and pages that did not scroll reliably when the cursor was over labels, cards, text boxes, or tables. This patch targets those real runtime problems.
