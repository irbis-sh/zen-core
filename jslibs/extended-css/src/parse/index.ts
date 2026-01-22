import * as CSSTree from 'css-tree';

import { extractStyleDeclarations, parseDeclarations } from './declarations';
import { parseASTSelectorList } from './selectorList';
import { Declaration, Rule } from './types';

export function parse(rules: string): Rule {
  const ast = CSSTree.parse(rules, { context: 'selectorList', positions: true }) as CSSTree.SelectorList;

  let declarations: Declaration[] | undefined;

  if (ast.children.size === 1) {
    const decl = extractStyleDeclarations(ast.children.first!);
    if (decl !== null) {
      declarations = parseDeclarations(decl);
    }
  }

  const selectorList = parseASTSelectorList(ast, rules);

  return declarations ? { type: 'style', declarations, selectorList } : { type: 'hide', selectorList };
}
