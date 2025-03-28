import './actions';

interface Secrets extends Secrets {
    AUTH0_CLIENT_ID: string;
    AUTH0_CLIENT_SECRET: string;
    DEBUG: string;
    ACTION_SECRET: string;
    ALLOWED_CLIENT_IDS: string;
}