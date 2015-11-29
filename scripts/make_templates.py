#!/usr/bin/env python3

import os

f = open("./src/mysteryshack/web/templates.rs", "w")

def w(s=''):
    if s:
        f.write(s)
    f.write('\n')

w("use handlebars::Handlebars;")
w("use handlebars_iron::HandlebarsEngine;")
w()

w("pub fn get_template_engine() -> HandlebarsEngine {")
w("    let mut registry = Handlebars::new();")

for fname in os.listdir("./src/templates/"):
    w("    registry.register_template_string(\"{name}\", "
      "include_str!(\"../../templates/{fname}\").to_owned()).unwrap();"
      .format(name=fname.replace(".hbs", ""), fname=fname))

w("    HandlebarsEngine::from2(registry)")
w("}")
