// Decorative, non-interactive background. Pure inline SVG + CSS — free, air-gap
// safe, no external assets. Security-themed: a radar sweep (scanning) + a node
// constellation (attack surface), over layered glows and a faint grid.

const NODES = [
  { x: 1180, y: 210, r: 4, big: true },
  { x: 1300, y: 320, r: 2.5 },
  { x: 1060, y: 300, r: 3 },
  { x: 1240, y: 120, r: 2.5 },
  { x: 980, y: 170, r: 3, big: true },
  { x: 1120, y: 430, r: 2.5 },
  { x: 1350, y: 470, r: 3 },
  { x: 900, y: 380, r: 2.5 },
  { x: 1010, y: 540, r: 3 },
  { x: 1270, y: 600, r: 2.5, big: true },
  { x: 830, y: 250, r: 2.5 },
  { x: 1160, y: 660, r: 2.5 },
];

const EDGES = [
  [0, 2],
  [0, 3],
  [0, 5],
  [2, 4],
  [4, 10],
  [1, 6],
  [5, 8],
  [8, 11],
  [9, 11],
  [1, 9],
  [2, 7],
  [7, 8],
  [0, 1],
  [3, 4],
];

const INDIGO = "rgb(139 124 246)";
const TEAL = "rgb(56 189 189)";

export function AppBackground() {
  return (
    <div className="app-bg" aria-hidden>
      <svg className="app-bg__scene" viewBox="0 0 1440 900" preserveAspectRatio="xMidYMid slice">
        <defs>
          <radialGradient id="sweepGrad" cx="0.5" cy="0.5" r="0.5">
            <stop offset="0%" stopColor={INDIGO} stopOpacity="0.35" />
            <stop offset="100%" stopColor={INDIGO} stopOpacity="0" />
          </radialGradient>
          <linearGradient id="sweepWedge" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor={INDIGO} stopOpacity="0.28" />
            <stop offset="100%" stopColor={INDIGO} stopOpacity="0" />
          </linearGradient>
        </defs>

        {/* Radar: concentric rings + crosshair + rotating sweep, top-right. */}
        <g transform="translate(1180 250)" className="app-bg__radar">
          {[70, 130, 195, 265, 340].map((r) => (
            <circle key={r} r={r} fill="none" stroke={INDIGO} strokeOpacity="0.1" strokeWidth="1" />
          ))}
          <line x1="-340" y1="0" x2="340" y2="0" stroke={INDIGO} strokeOpacity="0.07" />
          <line x1="0" y1="-340" x2="0" y2="340" stroke={INDIGO} strokeOpacity="0.07" />
          <g className="app-bg__sweep">
            <path d="M0 0 L340 -150 A340 340 0 0 1 340 150 Z" fill="url(#sweepWedge)" />
            <animateTransform
              attributeName="transform"
              type="rotate"
              from="0 0 0"
              to="360 0 0"
              dur="9s"
              repeatCount="indefinite"
            />
          </g>
          <circle r="70" fill="url(#sweepGrad)" />
        </g>

        {/* Constellation edges + nodes. */}
        <g strokeLinecap="round">
          {EDGES.map(([a, b], i) => (
            <line
              key={i}
              x1={NODES[a].x}
              y1={NODES[a].y}
              x2={NODES[b].x}
              y2={NODES[b].y}
              stroke={INDIGO}
              strokeOpacity="0.09"
              strokeWidth="1"
            />
          ))}
        </g>
        <g>
          {NODES.map((n, i) => (
            <circle
              key={i}
              cx={n.x}
              cy={n.y}
              r={n.r}
              fill={n.big ? TEAL : INDIGO}
              className="app-bg__node"
              style={{ animationDelay: `${(i % 6) * 0.7}s` }}
            />
          ))}
        </g>
      </svg>
    </div>
  );
}
