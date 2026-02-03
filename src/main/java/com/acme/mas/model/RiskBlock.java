package com.acme.mas.model;

import com.acme.mas.model.Enums.Rag;

public record RiskBlock(String name, Rag rag, String summary, Object evidence) {}
