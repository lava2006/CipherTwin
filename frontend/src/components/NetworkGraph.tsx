import { useMemo } from "react";
import type { TwinGraph, TwinNode } from "@/lib/types";

interface NetworkGraphProps {
  graph: TwinGraph;
  highlightNodeId?: string;
  onSelect?: (node: TwinNode) => void;
  width?: number;
  height?: number;
}

/**
 * Lightweight, dependency-free network visualization. Positions nodes on a
 * concentric layout by node type and renders SVG curves for relationships.
 */
export function NetworkGraph({
  graph,
  highlightNodeId,
  onSelect,
  width = 900,
  height = 520,
}: NetworkGraphProps) {
  const positioned = useMemo(() => {
    const groups: Record<string, TwinNode[]> = {};
    graph.nodes.forEach((n) => {
      groups[n.type] = groups[n.type] || [];
      groups[n.type].push(n);
    });
    const order = ["user", "device", "server", "database", "application", "iot", "honeypot"];
    const cx = width / 2;
    const cy = height / 2;
    const result: Record<string, { x: number; y: number }> = {};
    let maxRadius = Math.min(width, height) / 2 - 60;
    const types = order.filter((t) => groups[t]?.length);
    types.forEach((type, idx) => {
      const nodes = groups[type];
      const ringRadius = types.length === 1 ? 0 : (maxRadius * (idx + 1)) / types.length;
      nodes.forEach((node, i) => {
        const angle = (2 * Math.PI * i) / nodes.length;
        result[node.id] = {
          x: cx + ringRadius * Math.cos(angle),
          y: cy + ringRadius * Math.sin(angle),
        };
      });
    });
    return result;
  }, [graph, width, height]);

  const colorByType: Record<string, string> = {
    user: "#22d3ee",
    device: "#1f8ef1",
    server: "#8b5cf6",
    database: "#f59e0b",
    application: "#22c55e",
    iot: "#94a3b8",
    honeypot: "#f43f5e",
  };

  return (
    <div className="relative overflow-hidden rounded-lg border border-border bg-cyber-panel/60">
      <svg width="100%" height={height} viewBox={`0 0 ${width} ${height}`}>
        <defs>
          <radialGradient id="gridFade" cx="50%" cy="50%" r="60%">
            <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.06" />
            <stop offset="100%" stopColor="#22d3ee" stopOpacity="0" />
         </radialGradient>
       </defs>
        <rect width={width} height={height} fill="url(#gridFade)" />
        {/* edges */}
        {graph.edges.map((e, idx) => {
          const s = positioned[e.source];
          const t = positioned[e.target];
          if (!s || !t) return null;
          return (
            <line
              key={idx}
              x1={s.x}
              y1={s.y}
              x2={t.x}
              y2={t.y}
              stroke={highlightNodeId && (highlightNodeId === e.source || highlightNodeId === e.target) ? "#22d3ee" : "#1f8ef1"}
              strokeOpacity={highlightNodeId && (highlightNodeId === e.source || highlightNodeId === e.target) ? 0.7 : 0.18}
              strokeWidth={highlightNodeId && (highlightNodeId === e.source || highlightNodeId === e.target) ? 1.6 : 0.7}
            />
          );
        })}
        {/* nodes */}
        {graph.nodes.map((node) => {
          const p = positioned[node.id];
          if (!p) return null;
          const isHi = highlightNodeId === node.id;
          const isHoneypot = node.type === "honeypot" || node.tags?.includes("optimized_honeypot") || node.id === "decoy-ssh-01";
          const fill = node.status === "compromised" ? "#ef4444" : colorByType[node.type] || "#22d3ee";
          return (
            <g
              key={node.id}
              transform={`translate(${p.x}, ${p.y})`}
              onClick={() => onSelect?.(node)}
              style={{ cursor: onSelect ? "pointer" : "default" }}
            >
              {/* Pulsing ring for honeypot or highlighted nodes */}
              {(isHi || isHoneypot) && (
                <circle r={isHoneypot ? 18 : 14} fill={isHoneypot ? "#f43f5e" : fill} fillOpacity={0.2}>
                  <animate
                    attributeName="r"
                    from={isHoneypot ? "12" : "10"}
                    to={isHoneypot ? "24" : "20"}
                    dur={isHoneypot ? "2.5s" : "2s"}
                    repeatCount="indefinite"
                  />
                  <animate
                    attributeName="fill-opacity"
                    from="0.5"
                    to="0"
                    dur={isHoneypot ? "2.5s" : "2s"}
                    repeatCount="indefinite"
                  />
                </circle>
              )}
              {isHoneypot ? (
                <g>
                  <polygon
                    points="0,-11 11,0 0,11 -11,0"
                    fill="#f43f5e"
                    stroke="#fb7185"
                    strokeWidth={isHi ? 2.5 : 1.5}
                  />
                  <text
                    x={0}
                    y={3.5}
                    textAnchor="middle"
                    fill="#ffffff"
                    fontSize="9"
                    fontWeight="bold"
                    style={{ pointerEvents: "none" }}
                  >
                    🪤
                  </text>
                </g>
              ) : (
                <circle r={isHi ? 9 : 6} fill={fill} stroke="#0b1220" strokeWidth={1.5} />
              )}
              <text
                x={isHoneypot ? 14 : 10}
                y={4}
                fill={isHoneypot ? "#fda4af" : "#cbd5e1"}
                fontSize="9"
                fontWeight={isHoneypot ? "600" : "normal"}
                style={{ pointerEvents: "none" }}
              >
                {node.label}
              </text>
            </g>
          );
        })}
    </svg>
  </div>
  );
}
