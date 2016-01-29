#!/usr/bin/python

import mimetypes
import os

static_path = './src/static/'
output_file = "./src/mysteryshack/web/staticfiles.rs"
f = open(output_file, "w")

def w(s=''):
    if s:
        f.write(s)
    f.write('\n')

w("// Generated using scripts/make_static.py. Do NOT edit directly!")
w()

w('use router::Router;')
w('use hyper::header;')
w('use iron::prelude::*;')
w('use iron::modifiers::Header;')
w('use iron::status;')
w()
w('pub fn get_static_handler() -> Router {')
w('    let mut r = Router::new();')

def recurse_files(p):
    for dirpath, dirnames, filenames in os.walk(p):
        for filename in filenames:
            yield os.path.join(dirpath, filename)

for abs_filepath in sorted(recurse_files(static_path)):
    mimetype, encoding = mimetypes.guess_type(abs_filepath)
    contenttype = mimetype
    if encoding:
        contenttype += ' charset=' + encoding

    w('    r.get("/{route}", |_: &mut Request|\n'
      '        Ok(Response::with((\n'
      '            status::Ok,\n'
      '            Header(header::ContentType("{contenttype}".parse().unwrap())),\n'
      '            &include_bytes!("{filepath}")[..]\n'
      '        )))\n'
      '    );'
      .format(
          route=os.path.relpath(abs_filepath, static_path),
          contenttype=contenttype,
          filepath=os.path.relpath(abs_filepath, os.path.dirname(output_file))
      ))

w('    r')
w('}')
