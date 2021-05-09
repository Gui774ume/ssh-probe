\NeedsTeXFormat{LaTeX2e}%[1995/12/01] TODO: Add a date?
\ProvidesClass{sstic}[2020/05/26 SSTIC Proceedings style]

%%%%%%%%%
% Babel %
%%%%%%%%%
\RequirePackage[english,french,main=french]{babel}


\LoadClass[b5paper,11pt]{llncs}


%%%%%%%%%%%%%%%%%%%%%%%%%
% Class Option Handling %
%%%%%%%%%%%%%%%%%%%%%%%%%
\let\ifssticbw\iffalse
\let\ifssticpaper\iffalse
\DeclareOption{paper}{%
  \let\ifssticbw\iftrue%
  \let\ifssticpaper\iftrue%
}
\let\ifssticebook\iffalse
\DeclareOption{ebook}{\let\ifssticebook\iftrue}

\ProcessOptions


%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Fonts and similar stuff %
%%%%%%%%%%%%%%%%%%%%%%%%%%%
\RequirePackage[utf8x]{inputenc}
\ifssticebook
  \RequirePackage{textcomp}
%  \AtBeginDocument{\DeclareUnicodeCharacter{00A0}{~}}
\fi
\RequirePackage[fit]{truncate}
\RequirePackage{xspace}
\RequirePackage[T1]{fontenc}
\RequirePackage{microtype}     % Requires the cm-super Debian package
\RequirePackage{lmodern}
\RequirePackage{eurosym}
\RequirePackage{amsmath}
\RequirePackage{amssymb}
\RequirePackage{pifont}


%%%%%%%%%%%
% Headers %
%%%%%%%%%%%
\newcommand{\theshorttitle}{}
\newcommand\settitle[2][]{%
 \title{#2}%
 \ifthenelse{\equal{#1}{}}%
  {\renewcommand{\theshorttitle}{#2}\renewcommand\toctitle{#2}\titlerunning{#2}}%
  {\renewcommand{\theshorttitle}{#1}\renewcommand\toctitle{#1}\titlerunning={#1}}%
}

\newcommand{\theshortauthor}{}
\newcommand\setauthor[2][]{%
 \author{#2}%
 \ifthenelse{\equal{#1}{}}%
  {\renewcommand{\theshortauthor}{#2}\tocauthor{#2}\authorrunning{#2}}%
  {\renewcommand{\theshortauthor}{#1}\tocauthor{#1}\authorrunning{#1}}%
}

\ifssticebook
\else
  \RequirePackage{fancyhdr}

  \pagestyle{fancy}
  \fancyhf{}
  \setlength{\headheight}{16pt}
  \fancyhead[LE,RO]{\thepage}
  \fancyhead[RE]{\truncate{.90\headwidth}{\theshorttitle}}
  \fancyhead[LO]{\truncate{.90\headwidth}{\theshortauthor}}
\fi



%%%%%%%%%%%%%%%%%%%%%%%
% Graphics, tables... %
%%%%%%%%%%%%%%%%%%%%%%%
\RequirePackage[table]{xcolor}
\RequirePackage{graphicx}
\ifssticebook
\else
  % There seems to be an incompatibility here...
  \RequirePackage{pgfplots}
  \pgfplotsset{compat=1.11}
\fi
\RequirePackage{tabularx}
\RequirePackage{array}
\RequirePackage{longtable}
\RequirePackage{multirow}
\RequirePackage{lscape}
\RequirePackage{etoolbox}
\RequirePackage{subfigure}
\RequirePackage{verbatim}
\RequirePackage{pmboxdraw}
\RequirePackage{fancyvrb}
\RequirePackage[boxed]{algorithm}
\RequirePackage{tcolorbox}
\RequirePackage{booktabs}
\RequirePackage{rotating}
\RequirePackage{bytefield}
\RequirePackage{float}
\RequirePackage{multicol} % needed for the list of participants, index
\RequirePackage{caption}
\captionsetup{margin=10pt,font=footnotesize,labelfont=bf,labelsep=period}
\captionsetup[algorithm]{margin=10pt,font=footnotesize,labelfont=bf,labelsep=period,position=below}

\ifssticebook
  % use dvips, ebook readers don't cope to well with svg
  \def\pgfsysdriver{pgfsys-dvips.def}
  % htlatex uses latex in dvi mode so force the extension to something (either png or eps)
  \DeclareGraphicsExtensions{.eps, .png}
\else
  % tikz and pgf does not work with ebooks
  \RequirePackage{tikz}
  \RequirePackage{tikz-qtree}
  \usetikzlibrary{arrows,positioning}
  \usetikzlibrary{patterns}
  \usetikzlibrary{automata}
  \usetikzlibrary{calc}
  \RequirePackage[fancy]{tikz-inet}
  \usetikzlibrary{shapes,backgrounds}
  \usetikzlibrary{trees}
\fi


%%%%%%%%%%%%%%
% Listing... %
%%%%%%%%%%%%%%
\RequirePackage{listings}
\RequirePackage[noend]{algpseudocode}

\definecolor{grigri}{RGB}{233,232,234}
\lstset{breaklines=true,
        tabsize=4,
        boxpos=c,
        showstringspaces=false,
        basicstyle=\ttfamily\scriptsize,
        aboveskip=\bigskipamount,
        belowskip=\bigskipamount,
        captionpos=b,
        language=C,
        extendedchars=false
        basicstyle=\scriptsize\sffamily\color{darkgray},
        keywordstyle=\bfseries\color{purple},
        identifierstyle=\bfseries\color{black},
        commentstyle=\ttfamily\itshape\color{purple},
        stringstyle=\ttfamily\color{brown},
        showstringspaces=false,
        frame=leftline,
        backgroundcolor=\color{grigri},
        fillcolor=\color{grigri}}

\lstdefinelanguage{Rust}%
  {
   morekeywords={abstract,alignof,as,become,box,%
                 break,const,continue,crate,do,%
                 else,enum,extern,false,final,%
                 fn,for,if,impl,in,%
                 let,loop,macro,match,mod,%
                 move,mut,offsetof,override,priv,%
                 proc,pub,pure,ref,return,%
                 Self,self,sizeof,static,struct,%
                 super,trait,true,type,typeof,%
                 unsafe,unsized,use,virtual,where,%
                 while,yield},%
   sensitive,%
   morekeywords=[1]{\$},%
   morecomment=[s]{/*}{*/},%
   morecomment=[l]//,%
   morestring=[b]",%
%   morestring=[b]', Unfortunately lifetimes also use this and it
%   breaks
   classoffset=1,
   morekeywords={u8,u16,u32},keywordstyle=\color{blue},
   classoffset=0,
}[keywords,comments,strings]

\lstdefinelanguage{PowerShell}{
	morekeywords={Add-Content,Add-PSSnapin,Clear-Content,%
                Clear-History,Clear-Host,Clear-Item,%
                Clear-ItemProperty,Clear-Variable,%
                Compare-Object,Connect-PSSession,ConvertFrom-String,%
                Convert-Path,Copy-Item,Copy-ItemProperty,%
                Disable-PSBreakpoint,Disconnect-PSSession,%
                Enable-PSBreakpoint,Enter-PSSession,Exit-PSSession,%
                Export-Alias,Export-Csv,Export-PSSession,ForEach-Object,%
                Format-Custom,Format-Hex,Format-List,Format-Table,%
                Format-Wide,Get-Alias,Get-ChildItem,Get-Clipboard,%
                Get-Command,Get-ComputerInfo,Get-Content,Get-History,%
                Get-Item,Get-ItemProperty,Get-ItemPropertyValue,Get-Job,%
                Get-Location,Get-Member,Get-Module,Get-Process,%
                Get-PSBreakpoint,Get-PSCallStack,Get-PSDrive,Get-PSSession,%
                Get-PSSnapin,Get-Service,Get-TimeZone,Get-Unique,Get-Variable,%
                Get-WmiObject,Group-Object,help,Import-Alias,Import-Csv,%
                Import-Module,Import-PSSession,Invoke-Command,Invoke-Expression,%
                Invoke-History,Invoke-Item,Invoke-RestMethod,Invoke-WebRequest,%
                Invoke-WmiMethod,Measure-Object,mkdir,Move-Item,Move-ItemProperty,%
                New-object,New-Alias,New-Item,New-Module,New-PSDrive,New-PSSession,%
                New-PSSessionConfigurationFile,New-Variable,Out-GridView,%
                Out-Host,Out-Printer,Pop-Location,powershell_ise.exe,%
                Push-Location,Receive-Job,Receive-PSSession,Remove-Item,%
                Remove-ItemProperty,Remove-Job,Remove-Module,Remove-PSBreakpoint,%
                Remove-PSDrive,Remove-PSSession,Remove-PSSnapin,Remove-Variable,%
                Remove-WmiObject,Rename-Item,Rename-ItemProperty,Resolve-Path,%
                Resume-Job,Select-Object,Select-String,Set-Alias,Set-Clipboard,%
                Set-Content,Set-Item,Set-ItemProperty,Set-Location,%
                Set-PSBreakpoint,Set-TimeZone,Set-Variable,Set-WmiInstance,%
                Show-Command,Sort-Object,Start-Job,Start-Process,Start-Service,%
                Start-Sleep,Stop-Job,Stop-Process,Stop-Service,Suspend-Job,%
                Tee-Object,Trace-Command,Wait-Job,Where-Object,Write-Output%
	},
	morekeywords={Do,Else,For,ForEach,Function,If,In,Until,While},
	alsodigit={-},
	sensitive=false,
	morecomment=[l]{\#},
	morecomment=[n]{<\#}{\#>},
	morestring=[b]{"},
	morestring=[b]{'},
	morestring=[s]{@'}{'@},
	morestring=[s]{@"}{"@}
}

\lstloadlanguages{[Sharp]C,[x86masm]Assembler,java,PHP,C,Python}

% Change the style of listing numerotation
\AtBeginDocument{\renewcommand{\thelstlisting}{\arabic{lstlisting}}}


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Biblio, index and acronyms %
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\RequirePackage{makeidx}
\makeindex
\RequirePackage[nolist]{acronym}
\RequirePackage[sort]{cite}



%%%%%%%%%%%%%%%%%%%
% Babel switching %
%%%%%%%%%%%%%%%%%%%

\def\switcht@albion{%
\def\abstractname{Abstract.}
\def\ackname{Acknowledgement.}
\def\andname{and}
\def\lastandname{\unskip, and}
\def\appendixname{Appendix}
\def\chaptername{Chapter}
\def\claimname{Claim}
\def\conjecturename{Conjecture}
\def\contentsname{Table of Contents}
\def\corollaryname{Corollary}
\def\definitionname{Definition}
\def\examplename{Example}
\def\exercisename{Exercise}
\def\figurename{Fig.}
\def\keywordname{{\bf Key words:}}
\def\indexname{Index}
\def\lemmaname{Lemma}
\def\contriblistname{List of Contributors}
\def\listfigurename{List of Figures}
\def\listtablename{List of Tables}
\def\mailname{{\it Correspondence to\/}:}
\def\noteaddname{Note added in proof}
\def\notename{Note}
\def\partname{Part}
\def\problemname{Problem}
\def\proofname{Proof}
\def\propertyname{Property}
\def\propositionname{Proposition}
\def\questionname{Question}
\def\remarkname{Remark}
\def\seename{see}
\def\solutionname{Solution}
\def\subclassname{{\it Subject Classifications\/}:}
\def\tablename{Table}
\floatname{algorithm}{Algorithm}
\def\lstlistingname{\footnotesize Listing}
\def\theoremname{Theorem}}
\switcht@albion
% Names of theorem like environments are already defined
% but must be translated if another language is chosen
%
% French section
\def\switcht@francais{%\typeout{On parle francais.}%
\def\abstractname{R\'esum\'e.}%
\def\ackname{Remerciements.}%
\def\andname{et}%
\def\lastandname{ et}%
\def\appendixname{Appendice}
\def\chaptername{Chapitre}%
\def\claimname{Pr\'etention}%
\def\conjecturename{Hypoth\`ese}%
\def\contentsname{Table des mati\`eres}%
\def\corollaryname{Corollaire}%
\def\definitionname{D\'efinition}%
\def\examplename{Exemple}%
\def\exercisename{Exercice}%
\def\figurename{Fig.}%
\def\keywordname{{\bf Mots-cl\'e:}}
\def\indexname{Index}
\def\lemmaname{Lemme}%
\def\contriblistname{Liste des contributeurs}
\def\listfigurename{Liste des figures}%
\def\listtablename{Liste des tables}%
\def\mailname{{\it Correspondence to\/}:}
\def\noteaddname{Note ajout\'ee \`a l'\'epreuve}%
\def\notename{Remarque}%
\def\partname{Partie}%
\def\problemname{Probl\`eme}%
\def\proofname{Preuve}%
\def\propertyname{Caract\'eristique}%
\def\propositionname{Proposition}%
\def\questionname{Question}%
\def\remarkname{Remarque}%
\def\seename{voir}
\def\solutionname{Solution}%
\def\subclassname{{\it Subject Classifications\/}:}
\def\tablename{Tableau}%
\floatname{algorithm}{Algorithme}%
\def\lstlistingname{\footnotesize Listing}
\def\theoremname{Th\'eor\`eme}%
}


%%%%%%%%
% Misc %
%%%%%%%%
\RequirePackage{alltt}
\RequirePackage{ifthen}
\RequirePackage[hyphens]{url}
\RequirePackage[super]{nth}
\RequirePackage[binary-units=true]{siunitx}
\RequirePackage{fnpct}  % Manage footnote marks’ interaction with punctuation


%%%%%%%%%%%%%%%%%%%%%
% Internal commands %
%%%%%%%%%%%%%%%%%%%%%
\newcommand{\myclearpage}{\newpage{\pagestyle{empty}\cleardoublepage}}

\newcommand{\inputarticle}[1]{%
\bgroup
\input{#1/master}
\myclearpage
\egroup
\renewcommand{\thesection}{\arabic{section}}
}


%%%%%%%%%%%%%%%%%
% Stuff to sort %
%%%%%%%%%%%%%%%%%

\def\lastand{\ifnum\value{auco}=2\relax
                \unskip{} \andname\
             \else
                \unskip \lastandname\
             \fi}%
\def\and{\stepcounter{@auth}\relax
         \ifnum\value{@auth}=\value{auco}%
            \lastand
         \else
            \unskip,
         \fi}%


%%%%%%%%%%%%%%%%%%%%%%%%%
% hyperref must be last %
%%%%%%%%%%%%%%%%%%%%%%%%%

\ifssticpaper
  \newcommand{\pdfbookmark}{}
  \newcommand{\phantomsection}{}
  \newcommand{\href}[2]{#2}
  \newcommand{\hyperref}[2]{#1}
  \newcommand{\hypertarget}[2]{#2}
  \newcommand{\hyperlink}[2]{#2}
\else
  \RequirePackage{pdfpages}
  \RequirePackage[hidelinks]{hyperref}
  \makeatletter
    \renewcommand*{\toclevel@chapter}{-1}  % so that index looks like a chapter in toc but is at toplevel in pdfoutline
    \providecommand*{\toclevel@title}{0}  % so that articles titles appear in pdfoutline
    \def\toclevel@author{1000}  % so that articles authors do not appear as an additional entry in pdfoutline (this is kind of an ugly hack)
  \makeatother
\fi


%%%%%%%%%%%%%%%%%%%%%%%%%

\bibliographystyle{plain}

\sloppy

\endinput
