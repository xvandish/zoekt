package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"html/template"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/alecthomas/chroma"
	htmlf "github.com/alecthomas/chroma/formatters/html"
	"github.com/alecthomas/chroma/lexers"
	"github.com/alecthomas/chroma/styles"
)

func linkTag(nonce template.HTMLAttr, rel string, s string, m map[string]string) template.HTML {
	hash := m[strings.TrimPrefix(s, "/")]
	href := s + "?v=" + hash
	hashBytes, _ := hex.DecodeString(hash)
	integrity := "sha256-" + base64.StdEncoding.EncodeToString(hashBytes)
	return template.HTML(fmt.Sprintf(
		`<link%s rel="%s" href="%s" integrity="%s" />`,
		nonce, rel, href, integrity,
	))
}

func scriptTag(nonce template.HTMLAttr, s string, m map[string]string) template.HTML {
	hash := m[strings.TrimPrefix(s, "/")]
	href := s + "?v=" + hash
	hashBytes, _ := hex.DecodeString(hash)
	integrity := "sha256-" + base64.StdEncoding.EncodeToString(hashBytes)
	return template.HTML(fmt.Sprintf(
		`<script%s src="%s" integrity="%s"></script>`,
		nonce, href, integrity,
	))
}

type lineParts struct {
	Prefix      string
	Highlighted string
	Suffix      string
}

func splitCodeLineIntoParts(line string, bounds []int) lineParts {
	start := bounds[0]
	end := bounds[1]

	p := lineParts{
		Prefix:      line[0:start],
		Highlighted: line[start:end],
		Suffix:      line[end:],
	}

	return p
}

type CodePart struct {
	Line  string
	Match bool
}

func renderCodeLine(line string, bounds [][2]int) []CodePart {
	// process each bound at a time
	// keep track of the currentIdx into the string
	// at each bound.Left, if it's greater than currentIdx, we have a prefix
	// at each bound.Right, set currentIdx to bound.Right. If there are no more bounds left, then we have a suffix
	currIdx := 0
	lastBound := len(bounds) - 1

	var codeParts []CodePart

	for boundIdx, bound := range bounds {
		leftBound := bound[0]
		rightBound := bound[1]

		if bound[0] > currIdx {
			codeParts = append(codeParts, CodePart{
				Line:  line[currIdx:leftBound],
				Match: false,
			})
		}
		currIdx = rightBound

		codeParts = append(codeParts, CodePart{
			Line:  line[leftBound:rightBound],
			Match: true,
		})

		if boundIdx == lastBound && currIdx <= len(line) {
			codeParts = append(codeParts, CodePart{
				Line:  line[currIdx:],
				Match: false,
			})
		}
	}
	return codeParts
}

func getTreeItemLink(node *TreeNode, paddingLeft int, repoName, repoRev string, fileInPath bool) string {
	link := fmt.Sprintf("/experimental/%s/%s/%s/%s", repoName, node.Type, repoRev, node.Path)
	leftComp := imgLink
	btnCls := "arrow"
	if fileInPath {
		btnCls += " expanded"
	}
	buttonExpander := fmt.Sprintf("<button class=\"expander\"><div class=\"%s\" /></button>", btnCls)
	if node.Type == "tree" {
		leftComp = buttonExpander
	}

	// padding at the root is -15, explained below. However, we don't want to
	// render with -15px padding, so we normalize to 0.
	if paddingLeft < 0 {
		paddingLeft = 0
	}
	return fmt.Sprintf("<a style=\"padding-left:%dpx;\" data-path=\"%s\" data-hash=\"%s\" href=\"%s\">%s<span>%s</span></a>", paddingLeft, node.Path, repoRev, link, leftComp, node.Name)
}

var imgLink = "<img src=\"/assets/img/file-icon.svg\" width=\"16px\" height=\"16px\" />"

// -15?? good question.
// at the root, we don't want to append left padding, so root items sit flush.
// However, for ease of understanding, we always want to add +15 at every level.
// Except, the first, as stated before. So, to avoid exception checking that checks if
// we're at the first, and conditionally adds 15, we just start at -15, and always add
// 15.
var rootPadding = -15

// TODO: repo favorites!!! In the repo searcher, allow somone to pin
//  a repo as favorite so they can easily switch

// TODO: (lower priority) show the active branches at the top of the git
// selector

// not fun to read
func RenderDirectoryTree(rootDir *TreeNode, paddingLeft int, repoName, repoRev, filepath string) template.HTML {
	if rootDir == nil {
		return ""
	}

	cls := ""

	// if this rootNode has nothing to do with the open file (filepath)
	// close it, so the file tree isn't really busy

	// TODO: this could eventually be passed down in the recursive calls
	// so we aren't doing needless string comparisons
	// TODO: fix this for similarly named files in paths
	//  e.g names that start with filename but aren't exact
	fileInPath := strings.HasPrefix(filepath, rootDir.Path)

	// TODO: refactor file tree so that we can set a property on the parent element
	// and that will automatically take care of the child elements being hidden or
	// not

	outHtml := fmt.Sprintf("<div class=\"%s\"", cls)
	if paddingLeft == rootPadding {
		outHtml += "id=\"root\">"
	} else {
		outHtml += ">"

		// now, render either the folder name, or file name
		// if folder, it will later loop and render the children
		link := getTreeItemLink(rootDir, paddingLeft, repoName, repoRev, fileInPath)
		if rootDir.Type == "tree" {
			outHtml += fmt.Sprintf("<div>%s</div>", link)
		} else {
			isSelected := rootDir.Path == filepath
			cls := ""
			if isSelected {
				cls = "selected"
			}
			outHtml += fmt.Sprintf("<div class=\"%s\">%s%s</div>", cls, imgLink, link)
		}
	}

	// now, if a folder, loop through children
	if len(rootDir.Children) > 0 {
		// but first, add a containg div for all the children
		outerCls := "children"
		if fileInPath || paddingLeft == rootPadding {
			outerCls += " expanded"
		}
		outHtml += fmt.Sprintf("<div class=\"%s\">", outerCls)
		for _, child := range rootDir.Children {
			// now, we're at test (at least for the first iteration)

			// if the child has no children, just "render" it right away.
			// TODO: cleaner way to not include ul
			if len(child.Children) == 0 {
				// nextPadding := paddingLeft + 15
				// if left == 0 {
				// 	nextPadding = 0
				// }
				link := getTreeItemLink(child, paddingLeft+15, repoName, repoRev, fileInPath)
				isSelected := child.Path == filepath
				cls := ""
				if isSelected {
					cls = "selected"
				}
				outHtml += fmt.Sprintf("<div class=\"%s\">%s</div>", cls, link)
			} else {
				// fmt.Printf("at child with name=%s, depth=%d going to loop through its children.\n", child.Name, depth+1)
				outHtml += string(RenderDirectoryTree(child, paddingLeft+15, repoName, repoRev, filepath))
			}
		}
		outHtml += "</div>"
	}

	outHtml += "</div>"
	if paddingLeft == rootPadding {
		outHtml += "</nav>"
	}

	return template.HTML(outHtml)
}

// used to cap slice iteration
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// returns [:min(n|len(T))]
func getFirstNFiles(s []FileResult, n int) []FileResult {
	c := min(n, len(s))
	return s[:c]
}

func shouldInsertBlankLine(currIdx int, lines []ResultLine) bool {
	prevIdx := currIdx - 1
	if prevIdx < 0 {
		return false
	}

	return lines[currIdx].LineNumber-lines[prevIdx].LineNumber != 1
}

func getLineNumberLinkClass(bounds [][2]int) string {
	if len(bounds) > 0 {
		return "num-link match"
	}
	return "num-link"
}

func convertContentBlobToArrayOfLines(content string) []template.HTML {
	init := strings.Split(content, "\n")
	asHtml := make([]template.HTML, len(init))
	for idx, s := range init {
		asHtml[idx] = template.HTML(s)
	}

	return asHtml
}

type SyntaxHighlightedContent struct {
	Content []template.HTML
}

type SyntaxHighlightedLine template.HTML

// TODO(xvandish): Convert this function so that our build process can use it
// and inject it into our stylesheets. Right now, manual process.
func styleToCSS(style *chroma.Style) map[chroma.TokenType]string {
	classes := map[chroma.TokenType]string{}

	bg := style.Get(chroma.Background)

	for t := range chroma.StandardTypes {
		entry := style.Get(t)

		if t != chroma.Background {
			entry = entry.Sub(bg)
		}

		styleEntryCSS := htmlf.StyleEntryToCSS(entry)
		if styleEntryCSS != `` && classes[t] != `` {
			styleEntryCSS += `;`
		}
		classes[t] = styleEntryCSS + classes[t]
	}

	return classes
}

func getChromaClass(t chroma.TokenType) string {
	for t != 0 {
		if cls, ok := chroma.StandardTypes[t]; ok {
			if cls != "" {
				return cls
			}
			return ""
		}
		t = t.Parent()
	}
	if cls := chroma.StandardTypes[t]; cls != "" {
		return cls
	}
	return ""
}

func styleAttr(styles map[chroma.TokenType]string, tt chroma.TokenType) string {
	cls := getChromaClass(tt)
	if cls == "" {
		return ""
	}
	return fmt.Sprintf(` class="%s"`, cls)
}
func writeCSS(w io.Writer, style *chroma.Style) error {
	css := styleToCSS(style)

	tts := []int{}
	for tt := range css {
		tts = append(tts, int(tt))
	}
	sort.Ints(tts)
	for _, ti := range tts {
		tt := chroma.TokenType(ti)
		class := getChromaClass(tt)
		if class == "" {
			continue
		}
		styles := css[tt]
		if styles == "" {
			continue
		}
		if _, err := fmt.Fprintf(w, "/* %s */ .%schroma .%s { %s }\n", tt, "", class, styles); err != nil {
			return err
		}
	}
	return nil
}

func getLexerForFilename(filename string) chroma.Lexer {
	l := lexers.Match(filename)
	if l == nil {
		l = lexers.Fallback
	}
	fmt.Printf("using lexer: %s\n", l.Config().Name)
	return l
}

func getSyntaxHighlightedLine(line string, l chroma.Lexer) template.HTML {
	defer timeTrack(time.Now(), "getSyntaxHighlightedLine")
	if len(strings.TrimSpace(line)) == 0 {
		return template.HTML("<span></span>")
	}

	css := styleToCSS(styles.Xcode) // TODO: cache this!

	// TODO: check if getting the lexer failed

	l = chroma.Coalesce(l)

	it, err := l.Tokenise(nil, line)

	if err != nil {
		return template.HTML(line)
	}

	tokens := it.Tokens()

	var b strings.Builder
	for _, token := range tokens {
		html := html.EscapeString(token.String())
		attr := styleAttr(css, token.Type)
		b.WriteString(fmt.Sprintf("<span%s>%s</span>", attr, html))
	}

	return template.HTML(b.String())
}

func getSyntaxHighlightedContent(content, language, filename string) SyntaxHighlightedContent {
	defer timeTrack(time.Now(), fmt.Sprintf("getSyntaxHighlightedContent-%s", filename))
	l := lexers.Get(language)
	css := styleToCSS(styles.Xcode)

	if l == nil {
		fmt.Printf("unable to get lexer with language=%s. Trying via filename=%s\n", language, filename)
		l = lexers.Match(filename)
		if l == nil {
			fmt.Printf("failed to get lexer with filename. Not using a lexer and just splitting content.\n")
			return SyntaxHighlightedContent{
				Content: convertContentBlobToArrayOfLines(content),
			}
		} else {
			fmt.Printf("Found lexer=%s for filename=%s\n", l.Config().Name, filename)
		}
	}

	// Use the coalescing lexer to coalesce runs of idential token types into a single token
	l = chroma.Coalesce(l)

	it, err := l.Tokenise(nil, content)

	if err != nil {
		fmt.Printf("error tokenizing=%+v\n", err)
		return SyntaxHighlightedContent{
			Content: convertContentBlobToArrayOfLines(content),
		}
	}

	tokens := it.Tokens()

	lines := chroma.SplitTokensIntoLines(tokens)
	outLines := make([]template.HTML, len(lines))

	for idx, tokens := range lines {
		// we want to convert the line into its html equivalent
		// each line can have n tokens
		// each token is a span with (potentially) styling

		var b strings.Builder
		for _, token := range tokens {
			html := html.EscapeString(token.String())
			attr := styleAttr(css, token.Type)
			b.WriteString(fmt.Sprintf("<span%s>%s</span>", attr, html))
		}

		outLines[idx] = template.HTML(b.String())
	}

	return SyntaxHighlightedContent{
		Content: outLines,
	}
}

func getFuncs() map[string]interface{} {
	return map[string]interface{}{
		"loop":                             func(n int) []struct{} { return make([]struct{}, n) },
		"toLineNum":                        func(n int) int { return n + 1 },
		"linkTag":                          linkTag,
		"scriptTag":                        scriptTag,
		"splitCodeLineIntoParts":           splitCodeLineIntoParts,
		"min":                              min,
		"getFirstNFiles":                   getFirstNFiles,
		"shouldInsertBlankLine":            shouldInsertBlankLine,
		"getLineNumberLinkClass":           getLineNumberLinkClass,
		"renderCodeLine":                   renderCodeLine,
		"convertContentBlobToArrayOfLines": convertContentBlobToArrayOfLines,
		"getSyntaxHighlightedContent":      getSyntaxHighlightedContent,
		"renderDirectoryTree":              RenderDirectoryTree,
		"getDiffRowType":                   getDiffRowType,
		"getClassFromRowType":              getClassFromRowType,
		"getSyntaxHighlightedLine":         getSyntaxHighlightedLine,
		"getLexerForFilename":              getLexerForFilename,
	}
}

func LoadTemplates(base string, templates map[string]*template.Template) error {
	pattern := base + "/templates/common/*.html"
	common := template.New("").Funcs(getFuncs())
	common = template.Must(common.ParseGlob(pattern))

	pattern = base + "/templates/*.html"
	paths, err := filepath.Glob(pattern)
	log.Printf("paths=%+v\n", paths)
	if err != nil {
		return err
	}
	for _, path := range paths {
		t := template.Must(common.Clone())
		t = template.Must(t.ParseFiles(path))
		templates[filepath.Base(path)] = t
	}
	return nil
}

func LoadAssetHashes(assetHashFile string, assetHashMap map[string]string) error {
	file, err := os.Open(assetHashFile)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for k := range assetHashMap {
		delete(assetHashMap, k)
	}

	for scanner.Scan() {
		pieces := strings.SplitN(scanner.Text(), "  ", 2)
		hash := pieces[0]
		asset := pieces[1]
		(assetHashMap)[asset] = hash
	}

	return nil
}

func getDiffRowType(row IDiffRow) string {
	switch row.(type) {
	case IDiffRowAdded:
		return "added"
	case IDiffRowDeleted:
		return "deleted"
	case IDiffRowContext:
		return "context"
	case IDiffRowModified:
		return "modified"
	case IDiffRowHunk:
		return "hunk"
	default:
		return "blah"
	}
}

func getClassFromRowType(rowType string) string {
	switch rowType {
	case "hunk":
		return "hunk-row"
	default:
		return "row"
	}
}
