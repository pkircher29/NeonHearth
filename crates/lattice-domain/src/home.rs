use crate::DeviceId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use utoipa::ToSchema;
use uuid::Uuid;

/// Estimates below this confidence are treated as uncertain when no owner
/// placement exists (H11): the UI must prompt for placement instead of
/// rendering the device as confidently located.
pub const UNCERTAIN_CONFIDENCE_THRESHOLD: f32 = 0.6;
pub const MAX_FLOORS: usize = 64;
pub const MAX_WALLS_PER_FLOOR: usize = 4096;
pub const MAX_ROOMS_PER_FLOOR: usize = 1024;
pub const MIN_CEILING_HEIGHT_M: f64 = 1.8;
pub const MAX_CEILING_HEIGHT_M: f64 = 6.0;
/// Floor-local coordinates are bounded to keep geometry sane and match the
/// storage CHECK constraints.
pub const MAX_COORDINATE_M: f64 = 1000.0;
pub const MIN_NAME_CHARS: usize = 1;
pub const MAX_NAME_CHARS: usize = 128;

macro_rules! home_uuid_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, ToSchema)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }
            pub fn parse(value: &str) -> Result<Self, uuid::Error> {
                value.parse().map(Self)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

home_uuid_id!(
    /// One home per install for M5.
    HomeId
);
home_uuid_id!(FloorId);
home_uuid_id!(RoomId);
home_uuid_id!(WallId);
home_uuid_id!(OpeningId);
home_uuid_id!(PlacementId);

/// A point in floor-local metric coordinates (meters).
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OpeningKind {
    Door,
    Window,
    Stair,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Opening {
    pub opening_id: OpeningId,
    pub kind: OpeningKind,
    /// Distance from the wall start, along the wall, in meters.
    pub offset_m: f64,
    pub width_m: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Wall {
    pub wall_id: WallId,
    pub start: Point,
    pub end: Point,
    #[serde(default)]
    pub openings: Vec<Opening>,
}

impl Wall {
    pub fn length_m(&self) -> f64 {
        (self.end.x - self.start.x).hypot(self.end.y - self.start.y)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Room {
    pub room_id: RoomId,
    pub name: String,
    /// At least 3 points.
    pub polygon: Vec<Point>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Floor {
    pub floor_id: FloorId,
    /// Level 0 is the ground floor; negative levels are basements.
    pub level: i32,
    pub name: String,
    pub ceiling_height_m: f64,
    #[serde(default)]
    pub walls: Vec<Wall>,
    #[serde(default)]
    pub rooms: Vec<Room>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct HomePlan {
    pub home_id: HomeId,
    /// Increments on every committed save.
    pub version: u32,
    pub name: String,
    #[serde(default)]
    pub floors: Vec<Floor>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PlanValidationError {
    InvalidName {
        what: &'static str,
    },
    TooManyFloors {
        count: usize,
    },
    TooManyWalls {
        floor_id: FloorId,
        count: usize,
    },
    TooManyRooms {
        floor_id: FloorId,
        count: usize,
    },
    CeilingHeightOutOfRange {
        floor_id: FloorId,
        ceiling_height_m: f64,
    },
    CoordinateOutOfRange {
        what: &'static str,
    },
    DegenerateWall {
        wall_id: WallId,
    },
    PolygonTooSmall {
        room_id: RoomId,
        points: usize,
    },
    OpeningOutOfBounds {
        wall_id: WallId,
        opening_id: OpeningId,
    },
}

impl fmt::Display for PlanValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName { what } => {
                write!(
                    formatter,
                    "{what} must be {MIN_NAME_CHARS}..={MAX_NAME_CHARS} characters"
                )
            }
            Self::TooManyFloors { count } => {
                write!(formatter, "plan has {count} floors; at most {MAX_FLOORS}")
            }
            Self::TooManyWalls { floor_id, count } => {
                write!(
                    formatter,
                    "floor {floor_id} has {count} walls; at most {MAX_WALLS_PER_FLOOR}"
                )
            }
            Self::TooManyRooms { floor_id, count } => {
                write!(
                    formatter,
                    "floor {floor_id} has {count} rooms; at most {MAX_ROOMS_PER_FLOOR}"
                )
            }
            Self::CeilingHeightOutOfRange {
                floor_id,
                ceiling_height_m,
            } => {
                write!(
                    formatter,
                    "floor {floor_id} ceiling height {ceiling_height_m} outside {MIN_CEILING_HEIGHT_M}..={MAX_CEILING_HEIGHT_M} m"
                )
            }
            Self::CoordinateOutOfRange { what } => {
                write!(
                    formatter,
                    "{what} coordinate is not finite or outside +-{MAX_COORDINATE_M} m"
                )
            }
            Self::DegenerateWall { wall_id } => {
                write!(formatter, "wall {wall_id} has zero length")
            }
            Self::PolygonTooSmall { room_id, points } => {
                write!(
                    formatter,
                    "room {room_id} polygon has {points} points; at least 3 required"
                )
            }
            Self::OpeningOutOfBounds {
                wall_id,
                opening_id,
            } => {
                write!(
                    formatter,
                    "opening {opening_id} does not fit within wall {wall_id}"
                )
            }
        }
    }
}

impl std::error::Error for PlanValidationError {}

impl HomePlan {
    pub fn validate(&self) -> Result<(), PlanValidationError> {
        validate_name(&self.name, "plan name")?;
        if self.floors.len() > MAX_FLOORS {
            return Err(PlanValidationError::TooManyFloors {
                count: self.floors.len(),
            });
        }
        for floor in &self.floors {
            floor.validate()?;
        }
        Ok(())
    }
}

impl Floor {
    fn validate(&self) -> Result<(), PlanValidationError> {
        validate_name(&self.name, "floor name")?;
        if !(MIN_CEILING_HEIGHT_M..=MAX_CEILING_HEIGHT_M).contains(&self.ceiling_height_m) {
            return Err(PlanValidationError::CeilingHeightOutOfRange {
                floor_id: self.floor_id,
                ceiling_height_m: self.ceiling_height_m,
            });
        }
        if self.walls.len() > MAX_WALLS_PER_FLOOR {
            return Err(PlanValidationError::TooManyWalls {
                floor_id: self.floor_id,
                count: self.walls.len(),
            });
        }
        if self.rooms.len() > MAX_ROOMS_PER_FLOOR {
            return Err(PlanValidationError::TooManyRooms {
                floor_id: self.floor_id,
                count: self.rooms.len(),
            });
        }
        for wall in &self.walls {
            wall.validate()?;
        }
        for room in &self.rooms {
            room.validate()?;
        }
        Ok(())
    }
}

impl Wall {
    fn validate(&self) -> Result<(), PlanValidationError> {
        validate_point(self.start, "wall start")?;
        validate_point(self.end, "wall end")?;
        let length = self.length_m();
        if length <= 0.0 {
            return Err(PlanValidationError::DegenerateWall {
                wall_id: self.wall_id,
            });
        }
        for opening in &self.openings {
            let fits = opening.offset_m.is_finite()
                && opening.width_m.is_finite()
                && opening.offset_m >= 0.0
                && opening.width_m > 0.0
                && opening.offset_m + opening.width_m <= length;
            if !fits {
                return Err(PlanValidationError::OpeningOutOfBounds {
                    wall_id: self.wall_id,
                    opening_id: opening.opening_id,
                });
            }
        }
        Ok(())
    }
}

impl Room {
    fn validate(&self) -> Result<(), PlanValidationError> {
        validate_name(&self.name, "room name")?;
        if self.polygon.len() < 3 {
            return Err(PlanValidationError::PolygonTooSmall {
                room_id: self.room_id,
                points: self.polygon.len(),
            });
        }
        for point in &self.polygon {
            validate_point(*point, "room polygon")?;
        }
        Ok(())
    }
}

fn validate_name(value: &str, what: &'static str) -> Result<(), PlanValidationError> {
    let chars = value.chars().count();
    if (MIN_NAME_CHARS..=MAX_NAME_CHARS).contains(&chars) {
        Ok(())
    } else {
        Err(PlanValidationError::InvalidName { what })
    }
}

fn validate_point(value: Point, what: &'static str) -> Result<(), PlanValidationError> {
    let ok = |coordinate: f64| {
        coordinate.is_finite() && (-MAX_COORDINATE_M..=MAX_COORDINATE_M).contains(&coordinate)
    };
    if ok(value.x) && ok(value.y) {
        Ok(())
    } else {
        Err(PlanValidationError::CoordinateOutOfRange { what })
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Mounting {
    Wall,
    Ceiling,
    Floor,
    Shelf,
}

/// Owner-confirmed device placement. Authoritative: automatic estimates never
/// overwrite it (H4).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct OwnerPlacement {
    pub placement_id: PlacementId,
    pub device_id: DeviceId,
    pub floor_id: FloorId,
    pub x: f64,
    pub y: f64,
    pub height_m: Option<f64>,
    pub mounting: Option<Mounting>,
}

/// Automatic location estimate. Advisory only; stored separately from owner
/// placements and never claims an exact room from a single sensor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct LocationEstimate {
    pub device_id: DeviceId,
    pub floor_id: Option<FloorId>,
    pub room_id: Option<RoomId>,
    pub confidence: f32,
    pub evidence: Vec<String>,
    pub estimated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum EffectiveLocation {
    Owner(OwnerPlacement),
    Estimated {
        floor_id: Option<FloorId>,
        room_id: Option<RoomId>,
        confidence: f32,
    },
    Uncertain,
}

/// Owner placement always wins (H4). Without one, an estimate must reach
/// [`UNCERTAIN_CONFIDENCE_THRESHOLD`] to be treated as located; anything less
/// (or no estimate at all) is [`EffectiveLocation::Uncertain`].
pub fn effective_location(
    owner: Option<&OwnerPlacement>,
    estimate: Option<&LocationEstimate>,
) -> EffectiveLocation {
    if let Some(owner) = owner {
        return EffectiveLocation::Owner(owner.clone());
    }
    match estimate {
        Some(estimate) if estimate.confidence >= UNCERTAIN_CONFIDENCE_THRESHOLD => {
            EffectiveLocation::Estimated {
                floor_id: estimate.floor_id,
                room_id: estimate.room_id,
                confidence: estimate.confidence,
            }
        }
        _ => EffectiveLocation::Uncertain,
    }
}

/// Emitted after a committed plan save. Carries no geometry and no device
/// coordinates — clients refetch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct HomeChanged {
    pub home_id: HomeId,
    pub version: u32,
    pub summary: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventPayload;
    use chrono::TimeZone;

    fn point(x: f64, y: f64) -> Point {
        Point { x, y }
    }

    fn wall(start: Point, end: Point, openings: Vec<Opening>) -> Wall {
        Wall {
            wall_id: WallId::new(),
            start,
            end,
            openings,
        }
    }

    fn floor() -> Floor {
        Floor {
            floor_id: FloorId::new(),
            level: 0,
            name: "Ground".to_owned(),
            ceiling_height_m: 2.4,
            walls: vec![wall(
                point(0.0, 0.0),
                point(4.2, 0.0),
                vec![Opening {
                    opening_id: OpeningId::new(),
                    kind: OpeningKind::Door,
                    offset_m: 0.8,
                    width_m: 0.9,
                }],
            )],
            rooms: vec![Room {
                room_id: RoomId::new(),
                name: "Kitchen".to_owned(),
                polygon: vec![point(0.0, 0.0), point(4.0, 0.0), point(4.0, 3.0)],
            }],
        }
    }

    fn sample_plan() -> HomePlan {
        HomePlan {
            home_id: HomeId::new(),
            version: 1,
            name: "Home".to_owned(),
            floors: vec![floor()],
        }
    }

    fn estimate(confidence: f32) -> LocationEstimate {
        LocationEstimate {
            device_id: DeviceId::new(),
            floor_id: Some(FloorId::new()),
            room_id: Some(RoomId::new()),
            confidence,
            evidence: vec!["w6-rssi".to_owned(), "collector-arp".to_owned()],
            estimated_at: Utc.with_ymd_and_hms(2026, 8, 24, 12, 0, 0).unwrap(),
        }
    }

    fn placement() -> OwnerPlacement {
        OwnerPlacement {
            placement_id: PlacementId::new(),
            device_id: DeviceId::new(),
            floor_id: FloorId::new(),
            x: 1.5,
            y: 2.0,
            height_m: Some(1.1),
            mounting: Some(Mounting::Wall),
        }
    }

    #[test]
    fn valid_plan_passes_validation() {
        assert_eq!(sample_plan().validate(), Ok(()));
    }

    #[test]
    fn ceiling_height_outside_bounds_is_rejected() {
        for height in [1.79, 6.01, f64::NAN] {
            let mut plan = sample_plan();
            plan.floors[0].ceiling_height_m = height;
            assert!(matches!(
                plan.validate(),
                Err(PlanValidationError::CeilingHeightOutOfRange { .. })
            ));
        }
        for height in [1.8, 6.0] {
            let mut plan = sample_plan();
            plan.floors[0].ceiling_height_m = height;
            assert_eq!(plan.validate(), Ok(()));
        }
    }

    #[test]
    fn room_polygon_needs_at_least_three_points() {
        let mut plan = sample_plan();
        plan.floors[0].rooms[0].polygon.pop();
        assert!(matches!(
            plan.validate(),
            Err(PlanValidationError::PolygonTooSmall { points: 2, .. })
        ));
    }

    #[test]
    fn opening_must_fit_within_its_wall() {
        // Wall is 4.2 m long; 3.5 + 0.9 = 4.4 overruns the end.
        let mut plan = sample_plan();
        plan.floors[0].walls[0].openings[0].offset_m = 3.5;
        assert!(matches!(
            plan.validate(),
            Err(PlanValidationError::OpeningOutOfBounds { .. })
        ));

        let mut plan = sample_plan();
        plan.floors[0].walls[0].openings[0].offset_m = -0.1;
        assert!(matches!(
            plan.validate(),
            Err(PlanValidationError::OpeningOutOfBounds { .. })
        ));

        let mut plan = sample_plan();
        plan.floors[0].walls[0].openings[0].width_m = 0.0;
        assert!(matches!(
            plan.validate(),
            Err(PlanValidationError::OpeningOutOfBounds { .. })
        ));
    }

    #[test]
    fn zero_length_wall_is_rejected() {
        let mut plan = sample_plan();
        plan.floors[0].walls[0].openings.clear();
        plan.floors[0].walls[0].end = plan.floors[0].walls[0].start;
        assert!(matches!(
            plan.validate(),
            Err(PlanValidationError::DegenerateWall { .. })
        ));
    }

    #[test]
    fn out_of_range_coordinates_are_rejected() {
        let mut plan = sample_plan();
        plan.floors[0].walls[0].end = point(1000.1, 0.0);
        assert!(matches!(
            plan.validate(),
            Err(PlanValidationError::CoordinateOutOfRange { .. })
        ));

        let mut plan = sample_plan();
        plan.floors[0].rooms[0].polygon[0] = point(f64::NAN, 0.0);
        assert!(matches!(
            plan.validate(),
            Err(PlanValidationError::CoordinateOutOfRange { .. })
        ));
    }

    #[test]
    fn name_length_bounds_are_enforced() {
        let mut plan = sample_plan();
        plan.name = String::new();
        assert!(matches!(
            plan.validate(),
            Err(PlanValidationError::InvalidName { what: "plan name" })
        ));

        let mut plan = sample_plan();
        plan.floors[0].rooms[0].name = "r".repeat(129);
        assert!(matches!(
            plan.validate(),
            Err(PlanValidationError::InvalidName { what: "room name" })
        ));

        let mut plan = sample_plan();
        plan.floors[0].name = "f".repeat(128);
        assert_eq!(plan.validate(), Ok(()));
    }

    #[test]
    fn cardinality_caps_are_enforced() {
        let mut plan = sample_plan();
        plan.floors = (0..=MAX_FLOORS as i32)
            .map(|level| Floor {
                floor_id: FloorId::new(),
                level,
                name: "F".to_owned(),
                ceiling_height_m: 2.4,
                walls: Vec::new(),
                rooms: Vec::new(),
            })
            .collect();
        assert!(matches!(
            plan.validate(),
            Err(PlanValidationError::TooManyFloors { count }) if count == MAX_FLOORS + 1
        ));

        let mut plan = sample_plan();
        let template = plan.floors[0].walls[0].clone();
        plan.floors[0].walls = (0..=MAX_WALLS_PER_FLOOR)
            .map(|_| Wall {
                wall_id: WallId::new(),
                ..template.clone()
            })
            .collect();
        assert!(matches!(
            plan.validate(),
            Err(PlanValidationError::TooManyWalls { .. })
        ));

        let mut plan = sample_plan();
        let template = plan.floors[0].rooms[0].clone();
        plan.floors[0].rooms = (0..=MAX_ROOMS_PER_FLOOR)
            .map(|_| Room {
                room_id: RoomId::new(),
                ..template.clone()
            })
            .collect();
        assert!(matches!(
            plan.validate(),
            Err(PlanValidationError::TooManyRooms { .. })
        ));
    }

    #[test]
    fn contract_wire_shape_parses_and_round_trips() {
        let json = serde_json::json!({
            "home_id": "018f47a0-9b5c-7a22-8a33-112233445566",
            "version": 3,
            "name": "Home",
            "floors": [{
                "floor_id": "018f47a0-9b5c-7a22-8a33-112233445567",
                "level": 0,
                "name": "Ground",
                "ceiling_height_m": 2.4,
                "walls": [{
                    "wall_id": "018f47a0-9b5c-7a22-8a33-112233445568",
                    "start": {"x": 0.0, "y": 0.0},
                    "end": {"x": 4.2, "y": 0.0},
                    "openings": [{
                        "opening_id": "018f47a0-9b5c-7a22-8a33-112233445569",
                        "kind": "door",
                        "offset_m": 0.8,
                        "width_m": 0.9
                    }]
                }],
                "rooms": [{
                    "room_id": "018f47a0-9b5c-7a22-8a33-11223344556a",
                    "name": "Kitchen",
                    "polygon": [
                        {"x": 0.0, "y": 0.0}, {"x": 4.0, "y": 0.0},
                        {"x": 4.0, "y": 3.0}, {"x": 0.0, "y": 3.0}
                    ]
                }]
            }]
        });
        let plan: HomePlan = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(plan.validate(), Ok(()));
        assert_eq!(plan.version, 3);
        assert_eq!(plan.floors[0].walls[0].openings[0].kind, OpeningKind::Door);
        assert_eq!(serde_json::to_value(&plan).unwrap(), json);
    }

    #[test]
    fn owner_placement_always_wins() {
        let owner = placement();
        let confident = estimate(0.99);
        assert_eq!(
            effective_location(Some(&owner), Some(&confident)),
            EffectiveLocation::Owner(owner.clone())
        );
        assert_eq!(
            effective_location(Some(&owner), None),
            EffectiveLocation::Owner(owner)
        );
    }

    #[test]
    fn estimate_at_or_above_threshold_is_estimated() {
        for confidence in [0.6, 0.61, 1.0] {
            let estimate = estimate(confidence);
            assert_eq!(
                effective_location(None, Some(&estimate)),
                EffectiveLocation::Estimated {
                    floor_id: estimate.floor_id,
                    room_id: estimate.room_id,
                    confidence,
                }
            );
        }
    }

    #[test]
    fn low_confidence_or_missing_estimate_is_uncertain() {
        for confidence in [0.59, 0.0, f32::NAN] {
            assert_eq!(
                effective_location(None, Some(&estimate(confidence))),
                EffectiveLocation::Uncertain
            );
        }
        assert_eq!(effective_location(None, None), EffectiveLocation::Uncertain);
    }

    #[test]
    fn home_changed_event_round_trips_with_no_geometry() {
        let payload = EventPayload::HomeChanged(HomeChanged {
            home_id: HomeId::parse("018f47a0-9b5c-7a22-8a33-112233445566").unwrap(),
            version: 4,
            summary: "floor renamed".to_owned(),
        });
        let json = serde_json::to_value(&payload).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "type": "home_changed",
                "data": {
                    "home_id": "018f47a0-9b5c-7a22-8a33-112233445566",
                    "version": 4,
                    "summary": "floor renamed"
                }
            })
        );
        let data = json["data"].as_object().unwrap();
        assert_eq!(data.len(), 3, "event must carry no geometry fields");
        assert_eq!(
            serde_json::from_value::<EventPayload>(json).unwrap(),
            payload
        );
    }
}
