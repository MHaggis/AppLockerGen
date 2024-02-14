import streamlit as st
from code_editor import code_editor
import xml.etree.ElementTree as ET
import json

with open('resources/example_custom_buttons_bar_alt.json') as json_button_file_alt:
    custom_buttons_alt = json.load(json_button_file_alt)

with open('resources/example_info_bar.json') as json_info_file:
    info_bar = json.load(json_info_file)

with open('resources/example_code_editor_css.scss') as css_file:
    css_text = css_file.read()

mode_list = ["abap", "abc", "actionscript", "ada", "alda", "apache_conf", "apex", "applescript", "aql", "asciidoc", "asl", "assembly_x86", "autohotkey", "batchfile", "bibtex", "c9search", "c_cpp", "cirru", "clojure", "cobol", "coffee", "coldfusion", "crystal", "csharp", "csound_document", "csound_orchestra", "csound_score", "csp", "css", "curly", "d", "dart", "diff", "django", "dockerfile", "dot", "drools", "edifact", "eiffel", "ejs", "elixir", "elm", "erlang", "forth", "fortran", "fsharp", "fsl", "ftl", "gcode", "gherkin", "gitignore", "glsl", "gobstones", "golang", "graphqlschema", "groovy", "haml", "handlebars", "haskell", "haskell_cabal", "haxe", "hjson", "html", "html_elixir", "html_ruby", "ini", "io", "ion", "jack", "jade", "java", "javascript", "jexl", "json", "json5", "jsoniq", "jsp", "jssm", "jsx", "julia", "kotlin", "latex", "latte", "less", "liquid", "lisp", "livescript", "logiql", "logtalk", "lsl", "lua", "luapage", "lucene", "makefile", "markdown", "mask", "matlab", "maze", "mediawiki", "mel", "mips", "mixal", "mushcode", "mysql", "nginx", "nim", "nix", "nsis", "nunjucks", "objectivec", "ocaml", "partiql", "pascal", "perl", "pgsql", "php", "php_laravel_blade", "pig", "plain_text", "powershell", "praat", "prisma", "prolog", "properties", "protobuf", "puppet", "python", "qml", "r", "raku", "razor", "rdoc", "red", "redshift", "rhtml", "robot", "rst", "ruby", "rust", "sac", "sass", "scad", "scala", "scheme", "scrypt", "scss", "sh", "sjs", "slim", "smarty", "smithy", "snippets", "soy_template", "space", "sparql", "sql", "sqlserver", "stylus", "svg", "swift", "tcl", "terraform", "tex", "text", "textile", "toml", "tsx", "turtle", "twig", "typescript", "vala", "vbscript", "velocity", "verilog", "vhdl", "visualforce", "wollok", "xml", "xquery", "yaml", "zeek"]
btn_settings_editor_btns = [
    {
        "name": "copy",
        "feather": "Copy",
        "hasText": True,
        "alwaysOn": True,
        "commands": ["copyAll"],
        "style": {"top": "0rem", "right": "0.4rem"}
    },
    {
        "name": "update",
        "feather": "RefreshCw",
        "primary": True,
        "hasText": True,
        "showWithIcon": True,
        "commands": ["submit"],
        "style": {"bottom": "0rem", "right": "0.4rem"}
    }
]

st.set_page_config(
    page_title="⚒️ Modify AppLocker Policy",
    layout="wide",
    initial_sidebar_state="expanded",
)

def validate_xml(xml_string):
    try:
        ET.fromstring(xml_string)
        return True
    except ET.ParseError as e:
        return False

def parse_xml(xml_content):
    root = ET.fromstring(xml_content)
    hash_rules = []
    publisher_rules = []
    path_rules = []
    dll_rules = []
    script_rules = []

    for rule in root.iter('FileHashRule'):
        hash_rules.append(ET.tostring(rule, encoding='unicode'))

    for rule in root.iter('FilePublisherRule'):
        publisher_rules.append(ET.tostring(rule, encoding='unicode'))

    for rule in root.iter('FilePathRule'):
        path_rules.append(ET.tostring(rule, encoding='unicode'))

    for rule in root.iter('FilePathRule'):
        description_element = rule.find('Description')
        if description_element is not None:
            description_text = description_element.text
            if 'DLLs' in description_text:
                dll_rules.append(ET.tostring(rule, encoding='unicode'))
            elif 'scripts' in description_text:
                script_rules.append(ET.tostring(rule, encoding='unicode'))

    return hash_rules, publisher_rules, path_rules, dll_rules, script_rules

st.title("Modify AppLocker Policy")

uploaded_file = st.file_uploader("Upload AppLocker Policy XML file", type=['xml'])
if uploaded_file is not None:
    xml_content = uploaded_file.read().decode()
else:
    xml_content = st.text_area("Or paste your AppLocker Policy XML here")

if xml_content:
    if validate_xml(xml_content):
        original_hash_rules, original_publisher_rules, original_path_rules, original_dll_rules, original_script_rules = parse_xml(xml_content)

        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric(label="Hash Rules", value=len(original_hash_rules))
        col2.metric(label="Publisher Rules", value=len(original_publisher_rules))
        col3.metric(label="Path Rules", value=len(original_path_rules))
        col4.metric(label="DLL Rules", value=len(original_dll_rules))
        col5.metric(label="Script Rules", value=len(original_script_rules))

        comp_props = {"css": css_text, "globalCSS": ":root {\n  --streamlit-dark-font-family: monospace;\n}"}
        ace_props = {"style": {"borderRadius": "0px 0px 8px 8px"}}
        btns = custom_buttons_alt
        info = info_bar
        theme = "default"
        shortcuts = "vscode"
        wrap = True

        with st.expander("Settings", expanded=True):
            col_a, col_b, col_c, col_cb = st.columns([6,11,3,3])
            col_c.markdown('<div style="height: 2.5rem;"><br/></div>', unsafe_allow_html=True)
            col_cb.markdown('<div style="height: 2.5rem;"><br/></div>', unsafe_allow_html=True)

            height_type = col_a.selectbox("height format:", ["css", "max lines", "min-max lines"], index=2)
            if height_type == "css":
                height = col_b.text_input("height (CSS):", "400px")
            elif height_type == "max lines":
                height = col_b.slider("max lines:", 1, 40, 22)
            elif height_type == "min-max lines":
                height = col_b.slider("min-max lines:", 1, 40, (19, 22))

            col_d, col_e, col_f = st.columns([1,1,1])
            language = col_d.selectbox("lang:", mode_list, index=mode_list.index("xml"))
            theme = col_e.selectbox("theme:", ["default", "light", "dark", "contrast"])
            shortcuts = col_f.selectbox("shortcuts:", ["emacs", "vim", "vscode", "sublime"], index=2)
            focus = col_c.checkbox("focus", False)
            wrap = col_cb.checkbox("wrap", True)

        with st.expander("Components"):
            c_buttons = st.checkbox("custom buttons (JSON)", False)
            if c_buttons:
                response_dict_btns = code_editor(json.dumps(custom_buttons_alt, indent=2), lang="json", height=8, buttons=btn_settings_editor_btns, key="custom_buttons_editor")
                if response_dict_btns['type'] == "submit" and len(response_dict_btns['text']) != 0:
                    btns = json.loads(response_dict_btns['text'])

            i_bar = st.checkbox("info bar (JSON)", False)
            if i_bar:
                response_dict_info = code_editor(json.dumps(info_bar, indent=2), lang="json", height=8, buttons=btn_settings_editor_btns, key="info_bar_editor")
                if response_dict_info['type'] == "submit" and len(response_dict_info['text']) != 0:
                    info_bar = json.loads(response_dict_info['text'])


        with st.expander("Hash Rules"):
            hash_rules = code_editor("\n".join(original_hash_rules), lang='xml', height=250, theme=theme, shortcuts=shortcuts, buttons=btns, info=info, props=ace_props, options={"wrap": wrap}, key="hash_rules_editor")

        with st.expander("Publisher Rules"):
            publisher_rules = code_editor("\n".join(original_publisher_rules), lang='xml', height=250, theme=theme, shortcuts=shortcuts, buttons=btns, info=info, props=ace_props, options={"wrap": wrap}, key="publisher_rules_editor")

        with st.expander("Path Rules"):
            path_rules = code_editor("\n".join(original_path_rules), lang='xml', height=250, theme=theme, shortcuts=shortcuts, buttons=btns, info=info, props=ace_props, options={"wrap": wrap}, key="path_rules_editor")

        with st.expander("DLL Rules"):
            dll_rules = code_editor("\n".join(original_dll_rules), lang='xml', height=250, theme=theme, shortcuts=shortcuts, buttons=btns, info=info, props=ace_props, options={"wrap": wrap}, key="dll_rules_editor")

        with st.expander("Script Rules"):
            script_rules = code_editor("\n".join(original_script_rules), lang='xml', height=250, theme=theme, shortcuts=shortcuts, buttons=btns, info=info, props=ace_props, options={"wrap": wrap}, key="script_rules_editor")

        modified_xml_content = code_editor(xml_content, lang='xml', height=500, theme=theme, shortcuts=shortcuts, buttons=btns, info=info, props=ace_props, options={"wrap": wrap}, key="modified_xml_content_editor")

        if modified_xml_content['text'] != xml_content:
            if validate_xml(modified_xml_content['text']):
                st.markdown("### Modified Policy", unsafe_allow_html=True)
                st.code(modified_xml_content['text'], language="xml")
            else:
                st.error("The modified XML is not valid. Please check your changes and try again.")
        else:
            st.info("No changes were detected in the XML content.")
    else:
        st.error("The uploaded or pasted XML is not valid. Please check the XML content and try again.")
        
st.sidebar.image("assets/logo.png", width=250)