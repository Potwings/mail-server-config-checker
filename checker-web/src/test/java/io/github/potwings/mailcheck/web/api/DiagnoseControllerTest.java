package io.github.potwings.mailcheck.web.api;

import io.github.potwings.mailcheck.api.CheckContext;
import io.github.potwings.mailcheck.api.CheckResult;
import io.github.potwings.mailcheck.api.CheckStatus;
import io.github.potwings.mailcheck.engine.CheckEngine;
import io.github.potwings.mailcheck.engine.DiagnosisReport;
import io.github.potwings.mailcheck.engine.TargetIpResolver;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.isNull;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(DiagnoseController.class)
class DiagnoseControllerTest {

    @Autowired
    private MockMvc mvc;

    @MockitoBean
    private CheckEngine engine;

    @MockitoBean
    private TargetIpResolver targetIpResolver;

    @Test
    void 정상_도메인은_진단_결과를_반환한다() throws Exception {
        when(targetIpResolver.resolve(eq("example.com"), isNull()))
                .thenReturn(Optional.of(new TargetIpResolver.TargetIp("203.0.113.5", "MX(mx1)의 A 레코드에서 도출")));
        CheckResult spf = CheckResult.builder("spf", "SPF").status(CheckStatus.PASS).evidence("ok").build();
        when(engine.diagnose(any(CheckContext.class)))
                .thenReturn(new DiagnosisReport("example.com", "203.0.113.5", "MX(mx1)의 A 레코드에서 도출",
                        1234, List.of(spf)));

        mvc.perform(get("/api/v1/diagnose").param("domain", "Example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.domain").value("example.com"))
                .andExpect(jsonPath("$.targetIp").value("203.0.113.5"))
                .andExpect(jsonPath("$.results[0].checkId").value("spf"))
                .andExpect(jsonPath("$.results[0].status").value("PASS"));
    }

    @Test
    void 잘못된_도메인은_400과_에러_메시지() throws Exception {
        mvc.perform(get("/api/v1/diagnose").param("domain", "not a domain"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    void 잘못된_IP는_400() throws Exception {
        mvc.perform(get("/api/v1/diagnose").param("domain", "example.com").param("ip", "999.1.1.1"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void domain_파라미터_누락은_400() throws Exception {
        mvc.perform(get("/api/v1/diagnose"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").exists());
    }
}
