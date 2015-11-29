use handlebars::Handlebars;
use handlebars_iron::HandlebarsEngine;

pub fn get_template_engine() -> HandlebarsEngine {
    let mut registry = Handlebars::new();
    registry.register_template_string("index", include_str!("../../templates/index.hbs").to_owned()).unwrap();
    registry.register_template_string("dashboard", include_str!("../../templates/dashboard.hbs").to_owned()).unwrap();
    registry.register_template_string("login", include_str!("../../templates/login.hbs").to_owned()).unwrap();
    registry.register_template_string("oauth_entry", include_str!("../../templates/oauth_entry.hbs").to_owned()).unwrap();
    registry.register_template_string("layout", include_str!("../../templates/layout.hbs").to_owned()).unwrap();
    registry.register_template_string("oauth_error", include_str!("../../templates/oauth_error.hbs").to_owned()).unwrap();
    HandlebarsEngine::from2(registry)
}
