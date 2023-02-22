var mongoose = require('mongoose');

var Schema = mongoose.Schema;

var ReadingsSchema = new Schema(
    {
    _userId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'User' },
    sensor_id: {type: String, required: true, maxLength: 100},
    measurements: [
        {
            timestamp: {type: Date},
            sensor_reading: {type: Number},
        }
    ]}
);

module.exports = mongoose.model('readings', ReadingsSchema);