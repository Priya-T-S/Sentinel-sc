import { ArrowRight, Bot, CheckCircle2, CircleSlash, Cpu, GitMerge, MessagesSquare, ShieldCheck, Sparkles, TriangleAlert, XCircle } from 'lucide-react'
import { PageHeader } from '../components/Layout'
import { useScanGuard } from '../components/NoScan'
import { Callout, Card, EmptyState, KeyValue } from '../components/ui'
import { Link } from '../router'
import { useScan } from '../state'
import type { AgentRunInfo } from '../types'

const AGENT_TONE: Record<string, string> = {
  orchestrator: 'border-accent/50 bg-accent/5', vuln_intel: 'border-sev-high/40', package_trust: 'border-fuchsia-400/40',
  reachability: 'border-sev-medium/40', remediation: 'border-ok/40', reviewer: 'border-violet-400/50', assistant: 'border-ink-500 border-dashed',
}

function StatusIcon({ s }: { s: string }) {
  if (s === 'done') return <CheckCircle2 size={15} className="text-ok" />
  if (s === 'failed') return <XCircle size={15} className="text-bad" />
  if (s === 'skipped') return <CircleSlash size={15} className="text-ink-400" />
  return <Cpu size={15} className="text-accent" />
}

function fmtOut(v: unknown): string {
  if (v == null) return '—'
  if (typeof v === 'object') return Object.entries(v as Record<string, unknown>).map(([k, x]) => `${k}: ${x}`).join(', ') || '—'
  return String(v)
}

export function AgentsPage() {
  const guard = useScanGuard()
  const { result } = useScan()
  if (guard) return <><PageHeader title="Agents" />{guard}</>
  const o = result!.orchestration
  const rv = result!.review
  const ai = result!.ai
  if (!o || !rv) {
    return <><PageHeader title="Agents" /><div className="card"><EmptyState title="No agent trace for this scan" body="This scan was produced before the multi-agent orchestrator existed. Run a new scan." /></div></>
  }
  const runs = Object.fromEntries(o.agents.map((a) => [a.agent, a])) as Record<string, AgentRunInfo>
  const verdictTone = rv.verdict === 'approved' ? 'text-ok' : rv.verdict === 'approved_with_corrections' ? 'text-warn' : 'text-bad'
  const t0 = o.messages[0]?.t ?? 0
  return (
    <div className="fade-in">
      <PageHeader title="Agents" subtitle={o.principle} />

      <Card title={<span className="flex items-center gap-2"><GitMerge size={15} /> Execution plan</span>} subtitle="The orchestrator runs specialist agents in dependency order; step 1 runs in parallel." className="mb-4">
        <div className="flex flex-wrap items-stretch gap-2">
          {o.plan.map((step, i) => (
            <div key={step.step} className="flex items-stretch gap-2">
              <div className="rounded-xl border border-ink-700 bg-ink-900 p-3 min-w-[11rem] max-w-[15rem]">
                <div className="label mb-1.5">Step {step.step}{step.parallel ? ' · parallel' : ''}</div>
                <div className={`flex ${step.parallel ? 'flex-col gap-1.5' : ''}`}>
                  {step.agents.map((a) => (
                    <div key={a} className={`rounded-lg border px-2.5 py-1.5 text-sm text-ink-100 flex items-center gap-2 ${AGENT_TONE[a] || 'border-ink-600'}`}>
                      <StatusIcon s={runs[a]?.status || 'pending'} />{runs[a]?.title || a}
                    </div>
                  ))}
                </div>
                <div className="text-[11px] text-ink-400 mt-2">{step.why}</div>
              </div>
              {i < o.plan.length - 1 && <ArrowRight size={16} className="text-ink-500 self-center shrink-0" />}
            </div>
          ))}
        </div>
      </Card>

      <div className="grid lg:grid-cols-3 gap-4 mb-4">
        {o.agents.map((a) => (
          <div key={a.agent} className={`card card-pad border ${AGENT_TONE[a.agent] || ''}`}>
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-ink-100 font-semibold text-sm">{a.agent === 'assistant' ? <Sparkles size={15} className="text-fuchsia-300" /> : <Bot size={15} className="text-accent" />}{a.title}</div>
              <span className="flex items-center gap-1 text-xs text-ink-300"><StatusIcon s={a.status} />{a.status}{a.duration != null && ` · ${a.duration.toFixed(2)}s`}</span>
            </div>
            <p className="text-xs text-ink-400 mt-1.5">{a.role}</p>
            {Object.keys(a.outputs || {}).length > 0 && (
              <dl className="mt-3 grid grid-cols-[max-content_1fr] gap-x-3 gap-y-0.5 text-xs">
                {Object.entries(a.outputs).map(([k, v]) => (
                  <div key={k} className="contents"><dt className="text-ink-400">{k.replace(/_/g, ' ')}</dt><dd className="text-ink-100 mono break-words">{fmtOut(v)}</dd></div>
                ))}
              </dl>
            )}
            {a.error && <div className="text-xs text-bad mt-2">{a.error}</div>}
          </div>
        ))}
      </div>

      <Card title={<span className="flex items-center gap-2"><ShieldCheck size={15} className="text-violet-300" /> Independent Security Reviewer</span>}
        subtitle="Challenges every claim against its evidence. It can only downgrade claims — never add findings, mark anything safe, or raise confidence." className="mb-4">
        <div className={`text-2xl font-semibold uppercase ${verdictTone}`}>{rv.verdict.replace(/_/g, ' ')}</div>
        <p className="text-sm text-ink-300 mt-1">{rv.statement}</p>
        <div className="grid lg:grid-cols-2 gap-6 mt-4">
          {([['Pass 1 — claims (before scoring)', rv.pass1], ['Pass 2 — report consistency', rv.pass2]] as const).map(([title, checks]) => (
            <div key={title}>
              <div className="label mb-2">{title}</div>
              <table className="w-full text-sm"><tbody>
                {Object.entries(checks).map(([k, c]) => (
                  <tr key={k} className="border-b border-ink-800 align-top">
                    <td className="py-1.5 pr-2">{c.failed ? <TriangleAlert size={14} className="text-warn mt-0.5" /> : <CheckCircle2 size={14} className="text-ok mt-0.5" />}</td>
                    <td className="py-1.5 text-ink-200">{c.description}</td>
                    <td className="py-1.5 text-right tabular-nums text-xs text-ink-400 whitespace-nowrap pl-2">{c.checked} checked{c.failed ? <span className="text-warn"> · {c.failed} corrected</span> : ''}</td>
                  </tr>
                ))}
              </tbody></table>
            </div>
          ))}
        </div>
        {rv.corrections.length > 0 && (
          <div className="mt-4"><div className="label mb-1.5">Corrections applied ({rv.corrections.length})</div>
            <ul className="text-sm space-y-1">{rv.corrections.slice(0, 30).map((c, i) => (
              <li key={i} className="text-ink-300"><span className="chip bg-warn/10 text-warn mr-1.5">{c.check.replace(/_/g, ' ')}</span>
                <span className="mono text-xs text-ink-400">{c.target}</span> {String(c.before)} → {String(c.after)} — {c.reason}</li>))}</ul>
          </div>
        )}
        <div className="mt-4"><div className="label mb-1.5">Conflicts between agents ({rv.conflicts.length})</div>
          {rv.conflicts.length === 0 ? <p className="text-sm text-ink-400">No conflicting results.</p> : (
            <ul className="space-y-2">{rv.conflicts.map((c, i) => (
              <li key={i} className="rounded-lg border border-warn/30 bg-warn/5 px-3 py-2 text-sm">
                <div className="text-ink-100"><span className="chip bg-warn/15 text-warn mr-1.5">{c.type.replace(/_/g, ' ')}</span>{c.package}</div>
                <div className="text-ink-300 mt-0.5">{c.detail}</div>
                <div className="text-xs text-ink-400 mt-0.5">Suggested next step: {c.suggestion}</div>
                {ai?.conflict_notes?.filter((n) => n.conflict_index === i).map((n, j) => (
                  <div key={j} className="text-xs text-fuchsia-200 mt-1"><Sparkles size={11} className="inline mr-1" />AI note: {n.note} {n.next_steps.join(' · ')}</div>
                ))}
              </li>))}</ul>
          )}
        </div>
      </Card>

      <Card title={<span className="flex items-center gap-2"><Sparkles size={15} className="text-fuchsia-300" /> AI explanations (optional)</span>}
        subtitle="Explains reviewed evidence in plain language. A deterministic guard rejects output that contradicts the verdict; it never changes findings, scores or the policy decision." className="mb-4">
        {!ai?.enabled ? (
          <Callout title="Off">{ai?.reason || 'AI assistance is turned off.'} Enable it in <Link to="/settings" className="link">Settings → Privacy</Link> (requires ANTHROPIC_API_KEY on the server).</Callout>
        ) : ai.status === 'ok' ? (
          <>
            {ai.summary && <p className="text-sm text-ink-100 mb-3">{ai.summary}</p>}
            <KeyValue items={[
              ['Model', <span className="mono">{ai.served_by || ai.model}</span>],
              ['Findings explained', ai.explained],
              ['Rejected by guard', `${ai.guard_rejections?.length ?? 0}`],
              ['Tokens', `${ai.input_tokens ?? '?'} in / ${ai.output_tokens ?? '?'} out`],
              ['Estimated cost', ai.estimated_cost_usd != null ? `$${ai.estimated_cost_usd.toFixed(4)}` : null],
              ['Data sent', ai.data_sent],
            ]} />
            <p className="text-xs text-ink-400 mt-2">Explanations appear in each finding's detail panel, labelled as AI-generated.</p>
          </>
        ) : (
          <Callout tone="warn" title={ai.status === 'declined' ? 'Declined' : 'Error'}>{ai.status === 'declined' ? `The model declined (${ai.refusal_category ?? 'no category'}).` : ai.error} The scan result is unaffected.</Callout>
        )}
      </Card>

      <Card title={<span className="flex items-center gap-2"><MessagesSquare size={15} /> Agent message trace</span>} subtitle="What each agent reported, and to whom, in order.">
        <ol className="space-y-1.5 text-sm max-h-96 overflow-y-auto scrollbar-thin">
          {o.messages.map((m, i) => (
            <li key={i} className="flex gap-3">
              <span className="mono text-[11px] text-ink-500 w-14 shrink-0 text-right">+{(m.t - t0).toFixed(2)}s</span>
              <span className="text-xs shrink-0"><b className="text-ink-100">{runs[m.from]?.title || m.from}</b> <span className="text-ink-500">→ {m.to === 'all' ? 'all agents' : (runs[m.to]?.title || m.to)}</span></span>
              <span className="text-ink-300">{m.text}</span>
            </li>
          ))}
        </ol>
      </Card>
    </div>
  )
}
