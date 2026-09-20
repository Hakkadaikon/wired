// "MOQT" wordmark in the spirit of the 1976 NASA Graphics Standards Manual's
// logotype rules: one uniform stroke (cap height 70, stroke 10 = 1:7),
// arched forms, no crossbars, no outline/shadow/box. The colour comes from
// the surrounding text colour, so CSS decides red-on-white vs white-on-black.
export function Wordmark({ height = "1em" }: { height?: string }) {
  return (
    <svg
      viewBox="0 0 350 90"
      style={{ height, width: "auto", display: "block" }}
      fill="none"
      stroke="currentColor"
      strokeWidth="10"
      strokeLinecap="butt"
      role="img"
      aria-label="MOQT"
    >
      <path d="M5,70 V25 A20,20 0 0 1 45,25 V70 M45,70 V25 A20,20 0 0 1 85,25 V70" />
      <rect x="105" y="5" width="60" height="60" rx="25" />
      <rect x="190" y="5" width="60" height="60" rx="25" />
      <path d="M235,50 L268,83" />
      <path d="M272,5 H342 M307,5 V70" />
    </svg>
  );
}
