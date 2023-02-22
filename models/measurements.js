var mongoose = require('mongoose');

var Schema = mongoose.Schema;

var MeasurementsSchema = new Schema(
    {
    "timestamp": {type: Date},
    "sensor_reading": {type: Number},
    }
);

module.exports = mongoose.model('Measurements', MeasurementsSchema);