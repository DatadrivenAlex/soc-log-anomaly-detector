"""Lab geolocation and distance."""

from socdetect.geo import haversine_km, lookup


def test_london_to_singapore_is_intercontinental() -> None:
    distance = haversine_km(51.5074, -0.1278, 1.3521, 103.8198)
    assert 10_500 < distance < 11_200


def test_lab_map_covers_generator_ranges() -> None:
    london = lookup("198.51.100.30")
    singapore = lookup("203.0.113.80")
    new_york = lookup("192.0.2.40")
    assert london is not None and london.city == "London"
    assert singapore is not None and singapore.city == "Singapore"
    assert new_york is not None and new_york.city == "New York"
    assert lookup("8.8.8.8") is None
    assert lookup(None) is None
