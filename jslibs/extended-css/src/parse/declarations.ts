import * as CSSTree from 'css-tree';

import { Declaration } from './types';
import { getLiteral } from './utils/getLiteral';

export function extractStyleDeclarations(ast: CSSTree.CssNode): string | null {
  let style = null;

  CSSTree.walk(ast, {
    visit: 'PseudoClassSelector',
    enter(node, item, list) {
      if (node.name === 'style') {
        const arg = node.children?.first;
        if (arg == undefined) {
          throw new Error(':style() must have an argument');
        } else if (arg.type !== 'Raw') {
          throw new Error(`:style() argument must be 'Raw', got ${arg.type}`);
        }
        style = arg.value;
        list.remove(item);

        return this.break;
      }
    },
  });

  return style;
}

export function parseDeclarations(decl: string): Declaration[] {
  const declarations: Declaration[] = [];

  const ast = CSSTree.parse(decl, { context: 'declarationList', positions: true });

  CSSTree.walk(ast, {
    visit: 'Declaration',
    enter(node) {
      if (typeof node.important !== 'boolean') {
        throw new Error(
          `Expected declaration.important to be boolean, got ${node.important} of type ${typeof node.important}`,
        );
      }

      declarations.push({
        property: node.property,
        important: node.important,
        value: getLiteral(node.value, decl),
      });

      return this.skip; // Hint to skip walking into children.
    },
  });

  return declarations;
}
