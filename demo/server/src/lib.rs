//! Simulation helpers are not available to deployed consumers.
//! ```compile_fail
//! use demo_server::simulation::calculate_distance;
//! ```

pub mod flash_challenge;
pub mod handlers;
#[cfg(test)]
mod simulation;
pub mod state;
mod cache;
mod images;
mod verification_policy;
pub mod admission;
pub mod auth;
pub mod routes;

#[cfg(test)]
mod privacy_tests;

#[cfg(test)]
mod route_round_trip_tests;
