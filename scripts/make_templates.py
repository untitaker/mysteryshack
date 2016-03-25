#!/usr/bin/python

import os

f = open("./src/mysteryshack/web/templates.rs", "w")

def w(s=''):
    if s:
        f.write(s)
    f.write('\n')

w("// Generated using scripts/make_templates.py. Do NOT edit directly!")
w()

w("use handlebars::Handlebars;")
w("use handlebars_iron::HandlebarsEngine;")
w()

w("pub fn get_template_engine() -> HandlebarsEngine {")
w("    let mut registry = Handlebars::new();")

for fname in sorted(os.listdir("./src/templates/")):
    w("    registry.register_template_string(\"{name}\", "
      "include_str!(\"../../templates/{fname}\").to_owned()).unwrap();"
      .format(name=fname.replace(".hbs", ""), fname=fname))

w("    HandlebarsEngine::from(registry)")
w("}")
