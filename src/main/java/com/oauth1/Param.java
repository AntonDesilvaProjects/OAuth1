package com.oauth1;

import java.util.Objects;

public class Param implements Comparable<Param> {
    private String name;
    private String value;

    public Param(String name, String value) {
        this.name = name;
        this.value = value;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }


    @Override
    public int compareTo(Param o) {
        // first compare the name
        int nameComparison = this.getName().compareTo(o.getName());
        // then value
        return nameComparison == 0 ? this.getValue().compareTo(o.getValue()) : nameComparison;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Param)) return false;
        Param param = (Param) o;
        return Objects.equals(getName(), param.getName()) &&
                Objects.equals(getValue(), param.getValue());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getName(), getValue());
    }

    @Override
    public String toString() {
        return "Param{" +
                "name='" + name + '\'' +
                ", value='" + value + '\'' +
                '}';
    }
}
