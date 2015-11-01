use handlebars_iron::HandlebarsEngine;

pub fn get_engine() -> HandlebarsEngine {
    // FIXME: Templates folder is statted unnecessarily. See
    // https://github.com/sunng87/handlebars-iron/issues/18
    let rv = HandlebarsEngine::new("./templates/", ".hbs");
    {
        let mut hb = rv.registry.write().unwrap();
        hb.register_template_string("dashboard", include_str!("../../templates/dashboard.hbs").to_string()).unwrap();
        hb.register_template_string("index", include_str!("../../templates/index.hbs").to_string()).unwrap();
        hb.register_template_string("layout", include_str!("../../templates/layout.hbs").to_string()).unwrap();
        hb.register_template_string("login", include_str!("../../templates/login.hbs").to_string()).unwrap();
        hb.register_template_string("oauth_entry", include_str!("../../templates/oauth_entry.hbs").to_string()).unwrap();
        hb.register_template_string("oauth_error", include_str!("../../templates/oauth_error.hbs").to_string()).unwrap();
    }
    rv
}
