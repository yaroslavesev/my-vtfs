import App from '@errors/app';

export const client = {
    unauthorised: (message: string) => (
        new App(
            'UNAUTHORIZED',
            message,
            401,
        )
    ),

    badRequest: (message: string) => (
        new App(
            'BAD_REQUEST',
            message,
            422,
        )
    ),

    badParams: (message: string) => (
        new App(
            'BAD_PARAMS',
            message,
            400,
        )
    ),

    notFound: (message: string) => (
        new App(
            'NOT_FOUND',
            message,
            404,
        )
    ),

    conflict: (message: string) => (
        new App(
            'CONFLICT',
            message,
            409,
        )
    ),

    toManyRequest: (message: string) => (
        new App(
            'TO_MANY_REQUEST',
            message,
            429,
        )
    ),

    unavailable: (message: string) => (
        new App(
            'SERVICE_UNAVAILABLE',
            message,
            503,
        )
    ),

    unexpectedError: (message: string) => (
        new App(
            'SERVER_ERROR',
            message,
            500,
        )
    ),
};
