import {
  ApprovalIcon,
  ArrowIcon,
  CheckIcon,
  GateIcon,
  KeyIcon,
  ShieldIcon,
  TimelineIcon,
} from "../icons";

export function LandingPage({ onOpenConsole, onDemo, onQuickstart }: { onOpenConsole: () => void; onDemo: () => void; onQuickstart: () => void }) {
  const features = [
    {
      icon: ShieldIcon,
      title: "Tool-call authorization",
      text: "A deterministic policy engine decides before a high-impact tool can run.",
    },
    {
      icon: KeyIcon,
      title: "Tenant isolation",
      text: "Trusted API-key identity is bound to a tenant and checked against every target.",
    },
    {
      icon: ApprovalIcon,
      title: "Human approval",
      text: "Sensitive requests pause for exact-request, one-time operator authorization.",
    },
    {
      icon: GateIcon,
      title: "Prompt-injection signals",
      text: "Semantic signals can block suspicious actions but can never grant access.",
    },
    {
      icon: TimelineIcon,
      title: "Audit trail",
      text: "Append-only decision and approval events support review without storing raw prompts.",
    },
    {
      icon: CheckIcon,
      title: "MCP enforcement",
      text: "Guarded integrations keep tool implementations behind the authorization boundary.",
    },
  ];

  return (
    <div className="landing-page">
      <nav className="landing-nav" aria-label="Primary navigation">
        <a className="brand" href="/" aria-label="Agent Action Gate home">
          <span className="brand-mark"><GateIcon /></span>
          <span>Agent Action Gate</span>
        </a>
        <button className="button button-secondary" type="button" onClick={onQuickstart}>
          Developer quickstart
          <ArrowIcon />
        </button>
      </nav>

      <main>
        <section className="hero">
          <div className="hero-copy">
            <p className="eyebrow"><span className="live-dot" /> Runtime control plane</p>
            <h1>Runtime authorization for AI agents before high-impact tools execute.</h1>
            <p className="hero-lede">
              Block unsafe tool calls, require human approval for sensitive actions, isolate tenants, and keep an audit trail.
              Integrate over HTTP or MCP.
            </p>
            <div className="hero-actions">
              <button className="button button-primary" type="button" onClick={onDemo}>
                Try demo
                <ArrowIcon />
              </button>
              <button className="button button-secondary" type="button" onClick={onQuickstart}>Developer quickstart</button>
              <button className="text-link" type="button" onClick={onOpenConsole}>Operator console</button>
            </div>
          </div>

          <div className="decision-visual" aria-label="Agent action authorization flow">
            <div className="flow-node flow-agent">
              <span className="flow-index">01</span>
              <strong>Agent</strong>
              <small>Proposes a tool call</small>
            </div>
            <ArrowIcon className="flow-arrow" />
            <div className="flow-node flow-gate">
              <span className="gate-orbit" aria-hidden="true" />
              <span className="flow-index">02</span>
              <GateIcon />
              <strong>Action Gate</strong>
              <small>Normalizes · senses · decides</small>
            </div>
            <ArrowIcon className="flow-arrow" />
            <div className="flow-outcomes">
              <span className="outcome outcome-allow"><CheckIcon /> Allow</span>
              <span className="outcome outcome-approval"><ApprovalIcon /> Approval</span>
              <span className="outcome outcome-deny"><ShieldIcon /> Deny</span>
            </div>
            <ArrowIcon className="flow-arrow" />
            <div className="flow-node flow-tool">
              <span className="flow-index">03</span>
              <strong>Tool</strong>
              <small>Runs only when authorized</small>
            </div>
          </div>
        </section>

        <section className="principle-strip" aria-label="Core security principles">
          <p>Deterministic policy is the authority.</p>
          <span aria-hidden="true" />
          <p>Semantic risk is a sensor.</p>
          <span aria-hidden="true" />
          <p>Every unknown fails closed.</p>
        </section>

        <section className="feature-section" id="how-it-works">
          <div className="section-heading">
            <p className="eyebrow">Control at execution time</p>
            <h2>A narrow security boundary with clear responsibilities.</h2>
            <p>
              The gate does not claim to make an agent safe on its own. It provides a concrete place to enforce
              tenant, policy, approval, and audit controls before external side effects.
            </p>
          </div>
          <div className="feature-grid">
            {features.map(({ icon: Icon, title, text }) => (
              <article className="feature-item" key={title}>
                <span className="feature-icon"><Icon /></span>
                <h3>{title}</h3>
                <p>{text}</p>
              </article>
            ))}
          </div>
        </section>
      </main>

      <footer className="landing-footer">
        <a className="brand" href="/">
          <span className="brand-mark"><GateIcon /></span>
          <span>Agent Action Gate</span>
        </a>
        <p>Focused runtime authorization for agent tool calls.</p>
      </footer>
    </div>
  );
}
