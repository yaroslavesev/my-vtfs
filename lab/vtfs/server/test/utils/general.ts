import nock from 'nock';

beforeAll( () => {
    nock.disableNetConnect();
    jest.setTimeout(10000);
})

afterEach( () => {
    nock.cleanAll();
})
