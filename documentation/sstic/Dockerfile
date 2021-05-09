FROM ubuntu:20.04

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        ghostscript \
        libfontconfig \
        make \
        perl \
        wget \
    && wget -qO- "https://github.com/yihui/tinytex/raw/master/tools/install-unx.sh" | sh \
    && chmod a+x /root \
    && chmod -R a+r /root/.TinyTeX \
    && chmod -R a+rx /root/.TinyTeX/bin \
    && mv /root/bin/* /usr/local/bin/. \
    && tlmgr install \
        acronym \
        algorithmicx \
        algorithms \
        babel-english \
        babel-french \
        bigfoot \
        bytefield \
        caption \
        carlisle \
        cite \
        colortbl \
        environ \
        eurosym \
        fancyhdr \
        fnpct \
        hyphen-english \
        hyphen-french \
        koma-script \
        listings \
        microtype \
        multirow \
        nth \
        pdflscape \
        pdfpages \
        pgfplots \
        pmboxdraw \
        psnfss \
        siunitx \
        subfigure \
        tcolorbox \
        tikz-inet \
        tikz-qtree \
        translations \
        trimspaces \
        truncate \
        ucs \
        xstring \
    && apt-get purge -y --autoremove \
        ca-certificates \
        libfontconfig \
        perl \
        wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /SSTIC

ENTRYPOINT ["make"]
CMD []
