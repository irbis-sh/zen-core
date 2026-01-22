/**
 * Part of a final {@link Selector}. Takes a set of elements as its input and returns another set based on internal semantics.
 */
export interface Step {
  run(input: Element[]): Element[];
}

/**
 * CSS selector.
 *
 * @see {@link https://developer.mozilla.org/en-US/docs/Web/CSS/Guides/Selectors}
 */
export type Selector = Step[];

/**
 * CSS selector list.
 *
 * @see {@link https://developer.mozilla.org/en-US/docs/Web/CSS/Reference/Selectors/Selector_list}
 */
export type SelectorList = Selector[];

/**
 * Property and value pair, such as `color: red`, or `width: unset !important`.
 *
 * @see {@link https://developer.mozilla.org/en-US/docs/Web/CSS/Guides/Syntax/Introduction#css_declarations}
 */
export interface Declaration {
  property: string;
  value: string;
  important: boolean;
}

/**
 * Parsed CSS rule that hides elements matching the selector.
 */
export interface HideRule {
  type: 'hide';
  selectorList: SelectorList;
}

/**
 * Parsed canonical CSS rule, such as
 * ```css
 * .block-1, .block-2 {
 *   display: flex;
 *   flex-direction: row;
 * }
 * ```
 *
 * @see {@link https://developer.mozilla.org/en-US/docs/Web/CSS/Guides/Syntax/Introduction#css_rulesets}
 */
export interface StyleRule {
  type: 'style';
  selectorList: SelectorList;
  declarations: Declaration[];
}

export type Rule = HideRule | StyleRule;
