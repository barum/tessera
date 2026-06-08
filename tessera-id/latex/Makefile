# TesseraID whitepaper Makefile.
# Builds main.pdf via pdflatex + bibtex + pdflatex + pdflatex.

LATEX  ?= pdflatex
BIBTEX ?= bibtex
NAME   ?= main
PDF    ?= TesseraID_Whitepaper.pdf

.PHONY: all clean buildinfo

all: $(PDF)

# Regenerate the build-info include with the *current* UTC date/time.
buildinfo:
	@DATE=$$(date -u +"%B %-d, %Y"); \
	 TIME=$$(date -u +"%H:%M UTC"); \
	 printf '%% Auto-generated at build time. Do not edit.\n\\newcommand{\\buildDate}{%s}\n\\newcommand{\\buildTime}{%s}\n' "$$DATE" "$$TIME" > _buildinfo.tex; \
	 echo "Regenerated _buildinfo.tex: $$DATE $$TIME"

$(PDF): buildinfo $(NAME).tex references.bib $(wildcard sec*.tex)
	$(LATEX)  -interaction=nonstopmode -halt-on-error $(NAME).tex
	$(BIBTEX) $(NAME)
	$(LATEX)  -interaction=nonstopmode -halt-on-error $(NAME).tex
	$(LATEX)  -interaction=nonstopmode -halt-on-error $(NAME).tex
	cp $(NAME).pdf $(PDF)

clean:
	rm -f *.aux *.bbl *.blg *.log *.out *.toc *.synctex.gz $(NAME).pdf $(PDF)
