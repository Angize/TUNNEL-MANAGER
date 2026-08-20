#!/usr/bin/env python3
"""Every declared I18N key is reachable from the UI, and every key the UI asks for is declared.

A key nobody renders is dead weight, and they accumulate silently: nine of them survived several
rounds of feature removal because nothing ever looked. Deleting them by hand has a trap in the other
direction, which is the reason this is a guard and not a one-off sweep:

  1. The fa table is NOT one literal. `var I18N={fa:{...}}` is followed by several
     `(function(x){for(var k in x.fa)I18N.fa[k]=x.fa[k]})({fa:{...}})` chunks. Walking braces from the
     first one finds ~209 of ~790 keys, so most of the table never gets checked at all.
  2. A key BUILT at runtime looks dead. Nothing quotes `nav_logs` -- `T('nav_'+p.dataset.t)` composes
     it from the nav's `data-t="logs"`. Deleting it blanks a nav label with every other check green.

So a key counts as reachable when its name appears anywhere outside its declaration, OR when some
`T('prefix'+...)` call could compose it. The prefixes are DISCOVERED from the code, never hardcoded:
a new builder must not turn into a false failure here.

Read the DECODED INDEX_HTML, never the .py bytes -- in the source the escapes are still doubled.
"""
import os
import re
import sys

PANEL = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'tnl-central.py')


def decoded_index_html(src):
    m = re.search(r'INDEX_HTML\s*=\s*(r?)("""|\'\'\')(.*?)\2', src, re.S)
    if not m:
        sys.exit('i18n: INDEX_HTML not found in the panel source')
    html = m.group(3)
    if not m.group(1):
        html = html.encode('utf-8').decode('unicode_escape')
    return html


def fa_keys(html):
    """Every key declared in every {fa:{...}} chunk."""
    keys = {}
    chunks = [m.start() for m in re.finditer(r'\{fa:\{', html)]
    for st in chunks:
        i = html.index('{', st + 1)
        depth, j = 0, i
        while j < len(html):
            if html[j] == '{':
                depth += 1
            elif html[j] == '}':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        for k in re.findall(r'[\{,]\s*([A-Za-z_][A-Za-z0-9_]*)\s*:', html[i:j]):
            keys[k] = True
    return len(chunks), sorted(keys)


def quoted_keys(html):
    """Every T('name') call with a literal name. A missing one renders as an empty label, which no
    other guard sees: the row is there, the input works, and the text above it is simply gone."""
    return sorted(set(re.findall(r"T\(\s*'([A-Za-z0-9_]+)'\s*\)", html)
                      + re.findall(r'T\(\s*"([A-Za-z0-9_]+)"\s*\)', html)))


def builder_prefixes(html):
    """The prefixes of every T('xxx_'+...) call: keys they could compose are reachable."""
    return sorted(set(re.findall(r'T\(\s*[\'"]([A-Za-z0-9_]+_)[\'"]\s*\+', html)))


def main():
    with open(PANEL, encoding='utf-8') as f:
        html = decoded_index_html(f.read())

    nchunks, keys = fa_keys(html)
    prefixes = builder_prefixes(html)
    if nchunks < 2:
        sys.exit('i18n: found %d fa chunk(s) -- the collector is broken, not the table' % nchunks)
    if not keys:
        sys.exit('i18n: no keys collected -- the collector is broken')

    print('== I18N reachability ==')
    print('  ok  %d fa chunk(s), %d keys declared' % (nchunks, len(keys)))
    print('  ok  runtime key builders: %s' % (', '.join("T('%s'+…)" % p for p in prefixes) or 'none'))

    # Not `keys`: that list comes from walking the fa chunks, which is complete enough to find a
    # dead key and not complete enough to prove one absent. A declaration reads name:"...".
    missing = [k for k in quoted_keys(html) if (k + ':"') not in html]
    if missing:
        print()
        for k in missing:
            print(" FAIL T('%s') is rendered but never declared -- that label comes out blank" % k)
        print()
        print("%d undeclared key(s)." % len(missing))
        return 1
    print("  ok  every quoted key the UI asks for is declared")

    dead, composed = [], []
    for k in keys:
        if len(re.findall(r'\b' + re.escape(k) + r'\b', html)) > 1:
            continue                                   # rendered somewhere
        pre = next((p for p in prefixes if k.startswith(p)), None)
        if pre:
            composed.append((k, pre))
            continue
        dead.append(k)

    for k, pre in composed:
        print("  ok  %s is composed by T('%s'+…), not quoted" % (k, pre))
    if dead:
        print()
        for k in dead:
            print(' FAIL %s is declared and never rendered' % k)
        print('\n%d dead key(s). Delete the declaration -- but check first that no T(prefix+…) '
              'builds the name, or a live label goes blank with every other check still green.'
              % len(dead))
        return 1
    print('  ok  every declared key is rendered or composed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
