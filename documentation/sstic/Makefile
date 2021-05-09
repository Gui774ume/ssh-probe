#####################
# General Variables #
#####################

SRC=actes.tmp.tex $(wildcard */*.tex)
LATEX?=pdflatex
LFLAGS?=-halt-on-error

GSFLAGS=-sDEVICE=pdfwrite -dPDFSETTINGS=/prepress -dEmbedAllFonts=true -dCompatibilityLevel=1.4 -dNOPAUSE -dBATCH -dSubsetFonts=true -dOptimize=true -dNOPLATFONTS -dDOPDFMARKS -dSAFER -dSTRICT -dConvertCMYKImagesToRGB=false -dProcessColorModel=/DeviceCMYK -dDetectDuplicateImages=true

BIB_MISSING = 'No file.*\.bbl|Citation.*undefined'
REFERENCE_UNDEFINED='(There were undefined references|Rerun to get (cross-references|the bars) right)'



###################
# Ebook Variables #
###################

HTLATEX=htlatex
HTFLAGS?="xhtml,charset=utf-8" " -cunihtf -utf8"

# ebook metadata
CALFLAGS+=--book-producer STIC --publisher STIC
CALFLAGS+=--series SSTIC2020 --language fr

# IMGPDFS=$(wildcard */img/*.pdf */img/**/*.pdf)
# IMGEPSS=$(foreach img, $(IMGPDFS), $(img:pdf=eps))
# IMGJPGS=$(wildcard */img/*.jpg */img/**/*.jpg)
# IMGPNGS=$(foreach img, $(IMGJPGS), $(img:jpg=png))



###################
# Generic targets #
###################

.PHONY: default export clean from_docker from_docker_su


default: Makefile.standalone-targets

from_docker_su:
	sudo docker run --rm -it -v ${PWD}:/SSTIC:rw -u `id -u`:`id -g` sstic/actes

from_docker:
	docker run --rm -it -v ${PWD}:/SSTIC:rw -u `id -u`:`id -g` sstic/actes
# "-v ${PWD}:/SSTIC:rw" mount the current directory inside of the container (with RW access)
# "-u `id -u`:`id -g`" ensures that files written by the container belong to the current user

export: Makefile.standalone-targets


clean:
	rm -f *.aux *.bbl *.blg *.idx *.ilg *.ind *.log *.toc *.out
	rm -f _master.pdf
	rm -f _articles.tex 
	rm -f Makefile.standalone-targets
	rm -f *.tmp.tex *.tmp.pdf
	rm -f *.ebook.tex *.ebook.css *.ebook.dvi *.ebook.html *.ebook.4ct *.ebook.4tc
	rm -f *.ebook.idv *.ebook.lg *.ebook.pdf *.ebook.tmp *.ebook.xref
	rm -f actes.pdf actes-online.pdf



#######################
# Compilation helpers #
#######################

%.tmp.pdf: %.tmp.tex sstic.cls llncs.cls
	@rm -f $(@:.pdf=.aux) $(@:.pdf=.idx)
	$(LATEX) $(LFLAGS) $<
	bibtex $(@:.pdf=.aux) > /dev/null || true
	makeindex $(@:.pdf=.idx) > /dev/null 2> /dev/null || true
	$(LATEX) $(LFLAGS) $<
	@grep -Eqc $(BIB_MISSING) $(@:.pdf=.log) && $(LATEX) $< ; true
	@grep -Eqc $(REFERENCE_UNDEFINED) $(@:.pdf=.log) && $(LATEX) $<; true
	-grep --color '\(Warning\|Overful\).*' $(@:.pdf=.log) || true

%.pdf: %.tmp.pdf
	gs -sOutputFile=$@ $(GSFLAGS) $< < /dev/null > /dev/null

%-online.pdf: %-online.tmp.pdf
	gs -sOutputFile=$@ $(GSFLAGS) -dPrinted=false $< < /dev/null > /dev/null

%.tgz: %.pdf %
	@tar czf $@ $(@:.tgz=)/ $(@:.tgz=.pdf)
	@echo "Created $@." >&2; \



#######################
# Proceedings targets #
#######################

actes-online.tmp.tex: _master.tex
	cp $< $@

actes-online.tmp.pdf: _articles.tex $(SRC)


actes.tmp.pdf: _articles.tex $(SRC)

actes.tmp.tex: _master.tex
	@sed 's/{sstic}/[paper]{sstic}/' $< > $@



#################
# Ebook helpers #
#################

%.eps: %.pdf
	pdftocairo -eps $< $@

# TODO: Re-add stg to protect from GS attacks (restricted policy.xml)
#%.png: %.jpg
#	convert $< $@

%.ebook.html: %.ebook.tex sstic.cls llncs.cls
	@rm -f $(@:.html=.aux)
	$(HTLATEX) $< $(HTFLAGS) > /dev/null
	bibtex $(@:.html=) ||true
	$(LATEX) $(LFLAGS) $(@:.html=.tex)
	$(HTLATEX) $< $(HTFLAGS) > /dev/null
	-grep --color '\(Warning\|Overful\).*' $(@:.html=.log)
	@grep -Eqc $(BIB_MISSING) $(@:.html=.log) && $(HTLATEX) $< $(HTFLAGS) > /dev/null ; true
	@grep -Eqc $(REFERENCE_UNDEFINED) $(@:.html=.log) && $(HTLATEX) $< $(HTFLAGS) > /dev/null; true


# TODO: Re-add a way to include authors metadata properly, if needed
# TODO: What about the title?
# -include article/metadata.mk
# AUTHORS?=SSTIC
# CALFLAGS+=--authors $(AUTHORS)

%.epub: %.ebook.html
	ebook-convert $< $@ $(CALFLAGS)

%.mobi: %.ebook.html
	ebook-convert $< $@ $(CALFLAGS)

%.azw3: %.epub
# ebook-convert doesn't rasterize svgs for azw3, but Kindle svg parser seems
# buggy, so instead of doing html -> azw3 we do html -> epub -> azw3.
	ebook-convert $< $@ $(CALFLAGS)



###############################
# Specific standalone targets #
###############################

_articles.tex: $(SRC) Makefile
	@for d in [^_]*/; do \
		i=$$(basename "$$d"); \
		check_i=$$(echo "$$i" | tr -cd "a-zA-Z0-9_+-"); \
		if [ "$$i" = "$$check_i" ]; then \
			echo "\inputarticle{$$i}"; \
		fi; \
	done > $@

Makefile.standalone-targets: $(SRC) Makefile
	@for d in [^_]*/; do \
		i=$$(basename "$$d"); \
		[ -f "$$i/master.tex" ] || continue; \
		check_i=$$(echo "$$i" | tr -cd "a-zA-Z0-9_+-"); \
		if [ "$$i" = "$$check_i" ]; then \
			echo "# Targets for $$i"; \
			echo; \
			echo "$$i.tmp.tex: _standalone.tex"; \
			echo "	@sed 's/@@DIRECTORY@@/\$$(@:.tmp.tex=)/' _standalone.tex > \$$@"; \
			echo; \
			echo "$$i.ebook.tex: $$i.tmp.tex"; \
			echo "	@sed 's/{sstic}/[ebook]{sstic}/' \$$< > \$$@"; \
			echo; \
			printf "%s" "$$i.tmp.pdf: $$i.tmp.tex $$(echo $$i/*.tex)"; \
			ls $$i/*.bib > /dev/null 2> /dev/null && printf "%s" " $$(echo $$i/*.bib)"; \
			ls $$i/img/*.jpg > /dev/null 2> /dev/null && printf "%s" " $$(echo $$i/img/*.jpg)"; \
			ls $$i/img/*.png > /dev/null 2> /dev/null && printf "%s" " $$(echo $$i/img/*.png)"; \
			ls $$i/img/*.eps > /dev/null 2> /dev/null && printf "%s" " $$(echo $$i/img/*.eps)"; \
			ls $$i/img/*.pdf > /dev/null 2> /dev/null && printf "%s" " $$(echo $$i/img/*.pdf)"; \
			echo; \
			echo; \
			printf "%s" "$$i.ebook.html: $$i.ebook.tex $$(echo $$i/*.tex)"; \
			ls $$i/*.bib > /dev/null 2> /dev/null && printf "%s" " $$(echo $$i/*.bib)"; \
			ls $$i/img/*.jpg > /dev/null 2> /dev/null && printf "%s" " $$(echo $$i/img/*.jpg)"; \
			ls $$i/img/*.png > /dev/null 2> /dev/null && printf "%s" " $$(echo $$i/img/*.png)"; \
			ls $$i/img/*.eps > /dev/null 2> /dev/null && printf "%s" " $$(echo $$i/img/*.eps)"; \
			ls $$i/img/*.pdf > /dev/null 2> /dev/null && printf "%s" " $$(echo $$i/img/*.pdf)"; \
			echo; \
			echo; \
			printf "%s" "actes.tmp.pdf: $$i.tmp.tex $$(echo $$i/*.tex)"; \
			ls $$i/*.bib > /dev/null 2> /dev/null && printf "%s" " $$(echo $$i/*.bib)"; \
			ls $$i/img/*.jpg > /dev/null 2> /dev/null && printf "%s" " $$(echo $$i/img/*.jpg)"; \
			ls $$i/img/*.png > /dev/null 2> /dev/null && printf "%s" " $$(echo $$i/img/*.png)"; \
			ls $$i/img/*.eps > /dev/null 2> /dev/null && printf "%s" " $$(echo $$i/img/*.eps)"; \
			ls $$i/img/*.pdf > /dev/null 2> /dev/null && printf "%s" " $$(echo $$i/img/*.pdf)"; \
			echo; \
			echo; \
			echo "$$i-clean:"; \
			echo "	rm -f $$i.pdf $$i.azw3 $$i.epub $$i.mobi"; \
			echo; \
			echo "default: $$i.pdf"; \
			echo "clean: $$i-clean"; \
			echo "export: $$i.tgz"; \
			echo "Created targets for $$i." >&2; \
			echo; \
			echo; \
			echo; \
		else \
			echo "Ignoring invalid dir name ($$i)." >&2; \
		fi \
	done > Makefile.standalone-targets

-include Makefile.standalone-targets
