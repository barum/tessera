# tessera umbrella whitepaper Makefile.
# Builds the cross-project overview document.
# Mirrors tessera-id/latex/Makefile, tessera-hash/latex/Makefile, tessera-seal/latex/Makefile.

LATEX  ?= pdflatex
BIBTEX ?= bibtex
NAME   ?= main
PDF    ?= Tessera_Whitepaper.pdf

.PHONY: all clean buildinfo

all: $(PDF)

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
