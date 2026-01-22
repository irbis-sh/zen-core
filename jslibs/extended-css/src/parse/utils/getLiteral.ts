import { CssNode } from 'css-tree';

export function getLiteral(node: CssNode, raw: string) {
  return raw.slice(node.loc!.start.offset, node.loc!.end.offset);
}
