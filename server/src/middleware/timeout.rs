use axum::body::Body;
use axum::http::{Response, StatusCode};
use pin_project_lite::pin_project;
use std::time::Duration;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time::Sleep;
use tower::{Layer, Service};

#[derive(Debug, Clone)]
pub struct Timeout {
    timeout: Duration,
}

impl Timeout {
    pub fn new(timeout: Duration) -> Self {
        Timeout { timeout }
    }
}

impl<S> Layer<S> for Timeout {
    type Service = TimeoutService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TimeoutService::new(inner, self.timeout)
    }
}

#[derive(Debug, Clone)]
pub struct TimeoutService<S> {
    inner: S,
    timeout: Duration,
}

impl<S> TimeoutService<S> {
    fn new(inner: S, timeout: Duration) -> Self {
        TimeoutService { inner, timeout }
    }
}

impl<S, Request> Service<Request> for TimeoutService<S>
where
    S: Service<Request, Response = Response<Body>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let response_future = self.inner.call(request);
        let sleep = tokio::time::sleep(self.timeout);

        ResponseFuture {
            response_future,
            sleep,
        }
    }
}

pin_project! {
    pub struct ResponseFuture<F> {
        #[pin]
        response_future: F,
        #[pin]
        sleep: Sleep,
    }
}

impl<F, Error> Future for ResponseFuture<F>
where
    F: Future<Output = Result<Response<Body>, Error>>,
{
    type Output = Result<Response<Body>, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        match this.response_future.poll(cx) {
            Poll::Ready(result) => return Poll::Ready(result),
            Poll::Pending => {}
        }

        match this.sleep.poll(cx) {
            Poll::Ready(()) => {
                let response = Response::builder()
                    .status(StatusCode::REQUEST_TIMEOUT)
                    .body(Body::empty())
                    .unwrap();
                return Poll::Ready(Ok(response));
            }
            Poll::Pending => {}
        }

        Poll::Pending
    }
}
