# Tractrix documentation

Static HTML guides for [GitHub Pages](https://docs.github.com/en/pages).
This tree is the primary user documentation for Tractrix contracts
(`XmlHandler`, `Parser`, `XmlWriter`, features, security).

## Local preview

Open `index.html` in a browser, or serve the folder:

```bash
cd docs && python3 -m http.server 8000
```

## Publishing

On push to `main`/`master`, [`.github/workflows/pages.yml`](../.github/workflows/pages.yml)
deploys this directory. Enable **GitHub Pages** for the repository
(Settings → Pages → Source: GitHub Actions) if it is not already on.
