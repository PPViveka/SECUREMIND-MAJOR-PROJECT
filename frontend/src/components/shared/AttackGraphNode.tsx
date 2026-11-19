import { Handle, Position, type NodeProps, type Node } from '@xyflow/react';
import { LogIn, Code2, Crosshair } from 'lucide-react';

export type AttackNodeRole = 'entry' | 'function' | 'sink';

export type AttackFlowNode = Node<{ label: string; role: AttackNodeRole }, 'attack'>;

export const ROLE_STYLE: Record<AttackNodeRole, { color: string; caption: string }> = {
  entry: { color: '#4ade80', caption: 'Entry point' },
  function: { color: '#60a5fa', caption: 'Function' },
  sink: { color: '#f87171', caption: 'Dangerous sink' },
};

export function roleFromCriticality(criticality: string): AttackNodeRole {
  if (criticality === 'entry') return 'entry';
  if (criticality === 'critical' || criticality === 'high') return 'sink';
  return 'function';
}

const ICONS = { entry: LogIn, function: Code2, sink: Crosshair };

/** Circular graph node with its name underneath; handles sit on the circle's left and right. */
export function AttackGraphNode({ data }: NodeProps<AttackFlowNode>) {
  const { color } = ROLE_STYLE[data.role];
  const Icon = ICONS[data.role];
  const handleStyle = { opacity: 0, width: 6, height: 6, border: 'none', top: 22 };
  return (
    <div className="flex flex-col items-center" style={{ width: 150 }} title={`${ROLE_STYLE[data.role].caption}: ${data.label}`}>
      <div
        className="relative flex items-center justify-center rounded-full"
        style={{ width: 44, height: 44, background: '#0d1424', border: `2px solid ${color}`, boxShadow: `0 0 14px ${color}55` }}
      >
        <Icon style={{ color, width: 18, height: 18 }} />
        <Handle type="target" position={Position.Left} style={{ ...handleStyle, left: -3 }} />
        <Handle type="source" position={Position.Right} style={{ ...handleStyle, right: -3 }} />
      </div>
      <div className="mt-2 px-1 text-center font-mono text-[11px] leading-tight text-white/90 break-all">{data.label}</div>
    </div>
  );
}

export const attackNodeTypes = { attack: AttackGraphNode };
