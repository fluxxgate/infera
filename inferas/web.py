# inferas/web.py
"""
Minimal web scraper & HTML injector for inferas.
Sync-first implementation (requests + BeautifulSoup).
For JS-heavy sites, pair this with Playwright/selenium later.
"""

from typing import List, Dict, Optional, Union
import requests
import time
import random
from bs4 import BeautifulSoup, Tag, NavigableString

class scraper:
    def __init__(self, user_agent: Optional[str] = None, delay: tuple = (0.2, 1.0), timeout: int = 10, max_retries: int = 3):
        self.user_agent = user_agent or "inferas-scraper/0.1 (+https://github.com/yourname/inferas)"
        self.delay = delay
        self.timeout = timeout
        self.max_retries = max_retries
        self.last_html: Optional[str] = None
        self.last_url: Optional[str] = None
        self._soup: Optional[BeautifulSoup] = None

    def _polite_sleep(self):
        time.sleep(random.uniform(*self.delay))

    def getweb(self, link: str, headers: Optional[dict] = None, respect_delay: bool = True) -> str:
        """
        Fetch the given URL (sync). Stores the HTML & parsed soup on the instance.
        Returns raw HTML string.
        """
        headers = headers or {"User-Agent": self.user_agent}
        if respect_delay:
            self._polite_sleep()

        last_exc = None
        for attempt in range(self.max_retries):
            try:
                r = requests.get(link, headers=headers, timeout=self.timeout)
                r.raise_for_status()
                html = r.text
                self.last_html = html
                self.last_url = link
                self._soup = BeautifulSoup(html, "html.parser")
                return html
            except Exception as e:
                last_exc = e
                if attempt == self.max_retries - 1:
                    raise
                wait = 2 ** attempt
                # small console log for retries
                print(f"[inferas] retry {attempt+1} for {link} -> {e}; waiting {wait}s")
                time.sleep(wait)
        raise last_exc  # fallback (shouldn't normally reach)

    def _ensure_soup(self):
        if self._soup is None:
            if self.last_html:
                self._soup = BeautifulSoup(self.last_html, "html.parser")
            else:
                raise RuntimeError("No HTML loaded. call getweb(url) first.")

    def extractalltext(self, collapse_whitespace: bool = True) -> str:
        """
        Return page text (visible text only).
        Collapses repetitive whitespace by default.
        """
        self._ensure_soup()
        # remove script/style to avoid noise
        for s in self._soup(["script", "style", "noscript"]):
            s.decompose()

        texts = self._soup.stripped_strings
        if collapse_whitespace:
            return " ".join(texts)
        else:
            return "\n".join(texts)

    def extractallinteractions(self) -> List[Dict[str, Union[str, Dict]]]:
        """
        Returns a list of interactable elements found on the page:
        buttons, inputs, selects, textareas, links, forms.
        Each item: { type, text, attrs }
        """
        self._ensure_soup()
        out: List[Dict[str, Union[str, Dict]]] = []

        # helper to push an item
        def push(el: Tag, typ: str):
            text = el.get_text(strip=True) if el.get_text() else ""
            out.append({
                "type": typ,
                "text": text,
                "attrs": dict(el.attrs)
            })

        # buttons (including <button> and role=button)
        for b in self._soup.find_all(["button"]):
            push(b, "button")
        # inputs
        for i in self._soup.find_all("input"):
            push(i, f"input[{i.get('type','text')}]")
        # selects
        for s in self._soup.find_all("select"):
            push(s, "select")
        # textareas
        for t in self._soup.find_all("textarea"):
            push(t, "textarea")
        # anchors (links)
        for a in self._soup.find_all("a", href=True):
            push(a, "link")
        # forms
        for f in self._soup.find_all("form"):
            push(f, "form")
        # elements with onclick or role=button
        for e in self._soup.find_all(attrs={"onclick": True}):
            push(e, "onclick")
        for e in self._soup.find_all(attrs={"role": "button"}):
            push(e, "role=button")

        return out

    def get_element(self, el: str) -> List[str]:
        """
        Return outer HTML for all elements matching the CSS selector `el`.
        Example: get_element('div.article > h2')
        """
        self._ensure_soup()
        items = self._soup.select(el)
        return [str(i) for i in items]

    def get_by_class(self, _class: str) -> List[str]:
        """
        Find elements matching a class name (single class). Returns outer HTML list.
        """
        self._ensure_soup()
        items = self._soup.find_all(class_=_class)
        return [str(i) for i in items]

    def get_by_id(self, id: str) -> Optional[str]:
        """
        Return outer HTML for the element with the given id, or None.
        """
        self._ensure_soup()
        el = self._soup.find(id=id)
        return str(el) if el else None


class injection:
    """
    Simple HTML injection helpers that operate on provided HTML strings.
    These do NOT execute JS or run in a browser — they just return modified HTML.
    """

    @staticmethod
    def element(html: str, snippet: str, where: str = "end") -> str:
        """
        Inject `snippet` (raw HTML string) into `html`.
        `where` can be 'start'|'end'|'head'|'body-start'|'body-end'
        Returns modified HTML string.
        """
        soup = BeautifulSoup(html, "html.parser")
        # ensure there's a body
        if soup.body is None:
            # create a body if missing
            body = soup.new_tag("body")
            # move everything into body
            for child in list(soup.contents):
                body.append(child.extract())
            soup.append(body)

        snippet_soup = BeautifulSoup(snippet, "html.parser")
        if where in ("head", "start"):
            if soup.head is None:
                soup.html.insert(0, soup.new_tag("head"))
            soup.head.append(snippet_soup)
        elif where in ("body-start", "start-body"):
            soup.body.insert(0, snippet_soup)
        else:  # default to 'end' / 'body-end'
            soup.body.append(snippet_soup)

        return str(soup)

    @staticmethod
    def css(html: str, snippet: str, where: str = "head") -> str:
        """
        Inject a CSS block into the HTML. `snippet` should be raw CSS (not a <style> tag).
        Returns modified HTML string.
        """
        soup = BeautifulSoup(html, "html.parser")
        if soup.head is None:
            # create head if missing
            if soup.html is None:
                # create html root
                new_html = soup.new_tag("html")
                # move everything into html
                for child in list(soup.contents):
                    new_html.append(child.extract())
                soup.append(new_html)
            soup.html.insert(0, soup.new_tag("head"))

        style_tag = soup.new_tag("style")
        style_tag.string = snippet
        soup.head.append(style_tag)
        return str(soup)


# quick demo when run directly
if __name__ == "__main__":
    s = scraper()
    url = "https://example.com"
    print(f"[demo] fetching {url} ...")
    html = s.getweb(url)
    print("-> title:", s.get_element("title"))
    print("-> h1 text:", s.get_element("h1"))
    print("-> all text (first 200 chars):", s.extractalltext()[:200])
    print("-> interactions:", s.extractallinteractions())
