import { ElementType, JSX } from "react";

type LkSemanticTag = keyof JSX.IntrinsicElements;

export interface LkTextProps extends React.HTMLAttributes<HTMLElement> {
  fontClass?: LkFontClass;
  content?: string;
  color?: LkColor;
  tag?: LkSemanticTag;
  className?: string; // explicitly extracting because internal logic controls its rendering order
}

export default function Text({
  tag = "div",
  fontClass,
  color,
  children,
  style,
  className,
  ...restProps
}: LkTextProps) {
  const Tag = tag as ElementType;

  return (
    <Tag
      data-lk-component="text"
      className={`${fontClass || ""} ${color ? "color-" + color : ""} ${className || ""}`}
      style={style}
      {...restProps}
    >
      {children}
    </Tag>
  );
}
