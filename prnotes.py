import functools
import logging
import re
import time
from itertools import count
from subprocess import run

import keyring
import requests

log = logging.getLogger(__name__)

REPO = 'European-XFEL/EXtra-data'
MARKER = re.compile(r'^prnotes?\s?:', re.MULTILINE)

# Breaks in Markdown: https://spec.commonmark.org/0.30/#thematic-breaks
# This will also catch setext style headings, but they're hopefully rare in
# issue comments
MARKDOWN_HR = re.compile(r'^\s{,3}([-_*])\s*(?:\1\s*){2,}$', re.MULTILINE)
# Also a simplification: https://spec.commonmark.org/0.30/#list-items
MARKDOWN_BULLET = re.compile(r'[-*+]\s{1,4}')


def auth_main():
    from getpass import getpass
    print("Get a Github personal access token from:")
    print("  https://github.com/settings/personal-access-tokens/new")
    print("No permissions needed (for public repos).")
    token = getpass('Token (hidden input): ')
    keyring.set_password('https://api.github.com/', 'prnotes', token)


@functools.cache
def get_token():
    return keyring.get_password('https://api.github.com/', 'prnotes')


def github_api_req(url, **params):
    headers = {
        "User-Agent": "prnotes 0.1",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token := get_token():
        headers['Authorization'] = f"Bearer {token}"
    resp = requests.get(url, params=params, headers=headers)
    log.debug("Rate limit remaining: %s, resets in %d s",
              resp.headers.get('x-ratelimit-remaining'),
              float(resp.headers.get('x-ratelimit-reset')) - time.time(),
    )
    resp.raise_for_status()
    return resp.json()

def github_paged_req(url, **params):
    for i in count(start=1):
        yield github_api_req(url, page=i, **params)


def find_milestone_id(title):
    for j in github_paged_req(f'https://api.github.com/repos/{REPO}/milestones',
                              state='all', per_page=30):
        if not j:
            break

        for milestone in j:
            if milestone['title'] == title:
                return milestone['number']

    raise ValueError(f"No milestone found with title {title!r}")

def find_issues_for_milestone(mst_id: int):
    res = []
    for j in github_paged_req(f'https://api.github.com/repos/{REPO}/issues',
                              state='all', milestone=mst_id, per_page=100):
        res.extend(j)
        if len(j) < 100:
            break

    log.info("Found %d issues & PRs", len(res))
    return res

def find_prnote(issue: dict):
    is_pr = issue.get('pull_request') is not None
    itype = 'PR' if is_pr else 'Issue'
    print(f"Checking {itype} {issue['number']}...", end=" ")
    for j in github_paged_req(issue['comments_url'],
                              sort='created', direction='desc', per_page=100):
        for comment in j:
            if m := MARKER.search(comment['body']):
                print("Found note.")
                note = extract_prnote(m)
                note += f" ({itype} #{issue['number']})"
                # Blank-line after multi-line note
                if note.count('\n') > 0:
                    note += '\n'
                return note

        if len(j) < 100:
            print("No note.")
            return f"- {issue['title']} ({itype} #{issue['number']})"


def extract_prnote(match: re.Match):
    body = match.string
    oneline_note = body[match.end():].split('\n', 1)[0].strip()
    if oneline_note:
        # prnote: blah blah
        # Make bullet points a uniform format
        if bm := MARKDOWN_BULLET.match(oneline_note):
            oneline_note = oneline_note[bm.end():]

        return '- ' + oneline_note

    # prnote:
    # ...
    # (To end of comment or horizontal line: ----- )
    remainder = body[match.end():]
    return MARKDOWN_HR.split(remainder, maxsplit=1)[0].strip()


def main():
    import sys
    logging.basicConfig(level=logging.INFO)
    #mst_id = find_milestone_id(sys.argv[1])
    mst_id = 17
    issues = find_issues_for_milestone(mst_id)
    with open('prnotes-out.md', 'w') as f:
        for issue in issues:
            if note := find_prnote(issue):
                f.write(note + '\n')

    print("Converting to rst using pandoc...")
    run(['pandoc', '-f', 'markdown', '-t', 'rst', '-o', 'prnotes-out.rst', 'prnotes-out.md'])

if __name__ == '__main__':
    main()
