import { StrictMode, lazy, Suspense } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import Layout from "./components/Layout";
import { Spinner } from "./components/ui";
import "./index.css";
import AnalyzePage from "./pages/AnalyzePage";

const HistoryPage = lazy(() => import("./pages/HistoryPage"));
const DashboardPage = lazy(() => import("./pages/DashboardPage"));
const ScanPage = lazy(() => import("./pages/ScanPage"));
const CallShieldPage = lazy(() => import("./pages/CallShieldPage"));

const fallback = (
  <div className="flex justify-center py-16 text-ink-3">
    <Spinner />
  </div>
);

const router = createBrowserRouter([
  {
    element: <Layout />,
    children: [
      { path: "/", element: <AnalyzePage /> },
      { path: "/history", element: <Suspense fallback={fallback}><HistoryPage /></Suspense> },
      { path: "/scan/:id", element: <Suspense fallback={fallback}><ScanPage /></Suspense> },
      { path: "/dashboard", element: <Suspense fallback={fallback}><DashboardPage /></Suspense> },
      { path: "/call", element: <Suspense fallback={fallback}><CallShieldPage /></Suspense> },
    ],
  },
], { basename: import.meta.env.BASE_URL.replace(/\/$/, "") || "/" });

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
);
