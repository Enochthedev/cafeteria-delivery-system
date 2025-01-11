import { Document, model, Model, Schema, SchemaTimestampsConfig, SchemaType, Types } from 'mongoose';

export interface IUser extends Document, SchemaTimestampsConfig {
  username: string;
  matricNumber: string;
  email: string;
  password: string;
  phoneNumber?: string;
  location: {
    type: string;
    coordinates: [number, number]; // [longitude, latitude]
  };
  country: string;
  preferredPlatforms: Types.ObjectId;
  wallet: Types.ObjectId;
  hiddenRating: {
    paymentSpeed: number;
    siteUsage: number;
    averageCartSize: number;
    overall: number;
    averageIndividualshippingFee:number
  };
  referralCode?: string;
  referredBy?: string; // User ID
  betaUser: boolean;
  profileImage?: string;
}

// Define the User Schema
const UserSchema: Schema<IUser> = new Schema<IUser>(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    matricNumber: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
    },
    password: {
      type: String,
      required: true,
    },
    phoneNumber: {
      type: String,
      unique: true,
    },
    location: {
      type: {
        type: String,
        enum: ['Point'], // Supports GeoJSON
        default: 'Point',
      },
      coordinates: {
        type: [Number], // [longitude, latitude]
        required: true,
      },
    },
    country: {
      type: String,
      required: true,
    },
    preferredPlatforms: {
      type: Schema.Types.ObjectId,
      default: [], // e.g., ['AliExpress', 'Amazon', 'eBay']
    },
    wallet: {
      type: Schema.Types.ObjectId
    },
    hiddenRating: {
      paymentSpeed: {
        type: Number,
        min: 0,
        max: 5,
        default: 0,
      },
      siteUsage: {
        type: Number,
        min: 0,
        max: 5,
        default: 0,
      },
      averageCartSize: {
        type: Number,
        min: 0,
        max: 5,
        default: 0,
      },
      overall: {
        type: Number,
        min: 0,
        max: 5,
        default: 0,
      },
      averageIndividualshippingFee: {
        type: Number,
        default: 0
      }
    },
    referralCode: {
      type: String,
      unique: true,
    },
    referredBy: {
      type: Schema.Types.ObjectId,
      ref: 'User',
    },
    betaUser: {
      type: Boolean,
      default: false,
    },
    profileImage: {
      type: String, // URL to the image
    },
  },
  {
    timestamps: true, // Automatically adds createdAt and updatedAt fields
  }
);

// Add index for geospatial queries
UserSchema.index({ location: '2dsphere' });

// Define and export the User model
const User: Model<IUser> = model<IUser>('User', UserSchema);
export default User;